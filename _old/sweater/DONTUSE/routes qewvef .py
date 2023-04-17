from datetime import datetime

import sqlalchemy
from flask import render_template, redirect, session, request, abort, current_app
from flask_login import login_user, login_required, logout_user, current_user, AnonymousUserMixin
from flask_login.config import EXEMPT_METHODS
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

from sweater import app, login_manager, db
from sweater.models import User, Dish, Order


def decode_order(s):
    if not s.isnumeric():
        raise ValueError("Order string must only contain digits!")

    ids = []
    for i in range(0, len(s), 2):
        ids.append((int(s[i: i + 2])))

    return [Dish.query.filter_by(id=i).first() for i in ids]


def encode_order(dishes):
    res = ""
    for dish in dishes:
        res += str(dish.id).zfill(2)

    return res


def login_and_perms_required(perms):
    def wrapper(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if request.method in EXEMPT_METHODS or current_app.config.get("LOGIN_DISABLED"):
                pass
            elif not current_user.is_authenticated:
                return login_manager.unauthorized()
            elif current_user.permissions != perms:
                return login_manager.unauthorized()

            # flask 1.x compatibility
            # current_app.ensure_sync is only available in Flask >= 2.0
            if callable(getattr(current_app, "ensure_sync", None)):
                return current_app.ensure_sync(func)(*args, **kwargs)
            return func(*args, **kwargs)

        return decorated_view

    return wrapper


@app.route("/no-permissions")
def no_perms():
    return render_template("no_perms.html")


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if not current_user.is_authenticated:
        if request.method == "POST":
            login = request.form.get("login")
            password = request.form.get("password")
            user = User.query.filter_by(login=login).first()
            if user:
                print("found user")
                if check_password_hash(user.password, password):
                    login_user(user)
                    print("logged in")
                    return redirect("/")

        return render_template("login.html")
    print(current_user)
    return redirect("/")


@app.route("/", methods=["GET", "POST"])
@login_required
def hub():
    if current_user.permissions == "administrator":
        return redirect("/admin_menu")
    elif current_user.permissions == "staff":
        return redirect("/staff_menu")
    elif current_user.permissions == "student":
        return redirect("/home")

    raise ValueError(f"User {current_user.login} has unknown permissions!")


@app.route("/staff_menu")
@login_and_perms_required("staff")
def staff_menu():
    return render_template("staff_menu.html", user=current_user)


@app.route("/home", methods=["GET", "POST"])
@login_and_perms_required("student")
def home():
    current_orders = sorted(Order.query.filter_by(state="active", user_id=current_user.id), key=lambda i: i.date)
    return render_template("menu_stud.html", balance=current_user.balance, orders=current_orders)


@app.route("/home/order-<int:order_id>")
@login_required
def show_order(order_id):
    order = Order.query.filter_by(id=order_id).first()
    if order.user_id != current_user.id and current_user.permissions not in {"administrator", "staff"}:
        return no_perms

    dishes = decode_order(order.dishes)
    cost = sum(map(lambda i: i.price, dishes))
    return render_template("order_view.html", id=order_id, cost=cost, dishes=dishes, state=order.state)


@app.route("/home/add-order", methods=["POST", "GET"])
@login_and_perms_required("student")
def add_order():
    if session.get("new_order_dishes") is None:
        dishes = []
    else:
        dishes = [Dish.query.filter_by(id=id).first() for id in session.get("new_order_dishes")]

    return render_template(
        "add_order.html",
        dishes=dishes,
        cost=sum(map(lambda i: i.price, dishes))
    )


@app.route("/home/order-<int:order_id>/delete")
def delete_order(order_id):
    print("k;jlkbhnbhknjk")
    print(type(Order.query.filter_by(id=order_id)).first)
    db.session.delete(Order.query.filter_by(id=order_id).first())
    db.session.commit()
    return redirect("/")


@app.route("/home/add-order/confirm-order")
@login_required
def commit_order():
    if session.get("new_order_dishes") is None:
        return redirect("/")

    dishes = [Dish.query.filter_by(id=id).first() for id in session.get("new_order_dishes")]
    session["new_order_dishes"] = []
    order = Order(
        user_id=current_user.id,
        state="active",
        dishes=encode_order(dishes),
        date=datetime.now(),
        cost=sum(map(lambda i: i.price, dishes))
    )

    if len(dishes) > 0:
        db.session.add(order)
        db.session.commit()
    return redirect("/")


@app.route("/home/add-order/add-dish-to-order", methods=["GET"])
@login_required
def dish_choice_page():
    dishes = Dish.query.all()
    return render_template("dish_choice.html", dishes=dishes)


@app.route("/home/add-order/add-dish-to-order/add-<int:dish_id>")
@login_required
def add_dish_to_order(dish_id):
    dish = Dish.query.filter_by(id=dish_id).first()
    if session.get("new_order_dishes"):
        session["new_order_dishes"].append(dish.id)
    else:
        session["new_order_dishes"] = [dish.id]
    session.modified = True

    return redirect("/home/add-order")


@app.route("/home/add-order/delete-dish-<int:dish_id>")
@login_required
def delete_dish_from_order(dish_id):
    if dish_id in session["new_order_dishes"]:
        session["new_order_dishes"].pop(session["new_order_dishes"].index(dish_id))
        session.modified = True
    return redirect("/home/add-order")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/home/profile")
@login_and_perms_required("student")
def profile():
    return render_template("stud_profile.html", user=current_user)


@app.route("/admin_menu", methods=["GET"])
@login_and_perms_required("administrator")
def admin_page():
    return render_template("admin_page.html", user=current_user)


@app.errorhandler(404)
def in_progress(e):
    return render_template("in_progress_log.html", e=str(e).split()[0])


@app.route("/admin_menu/users", methods=["GET", "POST"])
@login_and_perms_required("administrator", )
def users_view():
    input_list = {'login': '', 'grade': '', 'name': '', 'surname': ''}
    people = User.query.all()
    if request.method == "POST":
        input_list['login'] = request.form.get("search-login")
        input_list['grade'] = request.form.get("search-grade")
        input_list['name'] = request.form.get("search-name")
        input_list['surname'] = request.form.get("search-surname")
        if request.form.get("search-login") or request.form.get("search-grade") or request.form.get("search-surname") \
                or request.form.get("search-name"):
            people = db.session.query(User).filter(User.login.like(f'%{request.form.get("search-login")}%'),
                                                   User.grade.like(f'%{request.form.get("search-grade")}%'),
                                                   User.name.like(f'%{request.form.get("search-name")}%'),
                                                   User.surname.like(f'%{request.form.get("search-surname")}%'))
    print(input_list)
    return render_template("users_view.html", users=people, inputs=input_list)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        user = User.query.filter_by(login=request.form.get("login")).first()
        if not (user is None):
            password_1 = request.form.get("password_1")
            password = request.form.get("password")
            password_2 = request.form.get("password_2")
            if check_password_hash(user.password, password_1) and password == password_2:
                user.password = generate_password_hash(password)
                db.session.commit()
                return redirect("/logout")
    return render_template("change_password.html")


@app.route("/admin_menu/dishes", methods=["GET", "POST"])
@login_and_perms_required("administrator")
def dishes():
    return render_template("dishes.html", dishes=Dish.query.all())


@app.route("/admin_menu/dishes/detailed-<int:id>", methods=["GET", "POST"])
@login_and_perms_required("administrator")
def more_inf(id):
    food = Dish.query.filter_by(id=id).first()
    return render_template("dishes_more.html", dish=food)


@app.route("/admin_menu/users/detailed-<string:login>", methods=["GET", "POST"])
@login_and_perms_required("administrator")
def detailed(login):
    person = User.query.filter_by(login=login).first()
    return render_template("more_inf.html", user=person)


@app.route("/home/profile/add-funds-<int:id>", methods=["GET", "POST"])
def fill(id):
    if request.method == "POST":
        if int(request.form.get("summa")) >= 0:
            user = User.query.filter_by(id=id).first()
            user.balance += int(request.form.get("summa"))
            db.session.commit()
            return redirect("/home/profile")
    return render_template("replanish_balance.html")


@app.route("/admin_menu/users/registartion", methods=["GET", "POST"])
def registration():
    if request.method == "POST":
        if User.query.filter_by(login=request.form.get("login")).first() is None:
            user = User(
                login=request.form.get("login"),
                permissions=request.form.get("permissions"),
                password=generate_password_hash(request.form.get("password")),
                name=request.form.get("name"),
                surname=request.form.get("surname"),
                grade=request.form.get("grade"),
                balance=0
            )
            if request.form.get("password_2") == request.form.get("password"):
                db.session.add(user)
                db.session.commit()
    return render_template("new_registration.html")
