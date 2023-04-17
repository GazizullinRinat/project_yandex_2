from datetime import datetime
from threading import Timer, Thread, Event
from pathlib import Path
from time import sleep

from flask_login import UserMixin
from sqlite3 import connect
from sqlalchemy import text

from sweater import db, login_manager, app


class Queue:
    def __init__(self):
        self.orders = []
        self.allowed_grades = tuple()

        self.start = Event()
        self.thread = Thread(target=self.update)
        self.start.set()
        self.thread.start()

    def get_order(self):
        if self.orders:
            return self.orders[-1]
        else:
            return []

    def set_allowed_grades(self, grades):
        self.allowed_grades = grades

    def update(self):
        while self.start.is_set():
            with app.app_context():
                self.orders = []
                orders = [Order.query.get(i) for i in db.session.execute(text("SELECT id FROM 'order'")).all()]

                for order in orders:
                    grade = db.session.execute(text(f"SELECT grade FROM 'user' WHERE id = {order.user_id}")).first()[0]
                    state = order.state

                    if grade.isnumeric():
                        grade = int(grade)
                    else:
                        grade = int(grade[:-1])

                    if grade in self.allowed_grades and state == "active":
                        self.orders.append(order)

                sleep(1)

    def start(self):
        self.start.set()

    def stop(self):
        self.start.clear()


class User(db.Model, UserMixin):
    id = db.Column("id", db.Integer, primary_key=True)
    login = db.Column("login", db.String(128), unique=True)
    permissions = db.Column("permissions", db.String(16), default="student")
    password = db.Column("password", db.String(256), nullable=False)
    name = db.Column("name", db.String(128))
    surname = db.Column("surname", db.String(128))
    grade = db.Column("grade", db.String(4))
    balance = db.Column("balance", db.Integer, default=0)

    def __repr__(self):
        return f"<User {self.login}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Dish(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    price = db.Column("price", db.Integer, nullable=False)
    title = db.Column("title", db.String(50), default="Dish")
    image_url = db.Column("image_url", db.String(100), default="static/placeholder.png")
    description = db.Column("description", db.String(300))

    def __repr__(self):
        return f"<Dish {self.id}>"


class Order(db.Model):
    id = db.Column("id", db.Integer, primary_key=True)
    user_id = db.Column("user_id", db.Integer, nullable=False)
    state = db.Column("state", db.String, default="active")
    dishes = db.Column("dishes", db.String)
    date = db.Column("date", db.DateTime)
    cost = db.Column("cost", db.Integer)

    def __repr__(self):
        return f"<Order {self.id}>"