from datetime import datetime
from threading import Timer, Thread, Event
from pathlib import Path
from time import sleep

from flask_login import UserMixin
from sqlite3 import connect

from sweater import db, login_manager


class Queue:
    def __init__(self, timetable):
        self.path = Path(__file__).parent.parent.absolute().joinpath(Path("instance/data.db"))
        self.orders = []
        if timetable:
           self.timetable = timetable
        else:
            self.timetable = [
                ((10, 0), (6, 7)),
                ((11, 0), (8, 9)),
                ((22, 0), (10, 11)),
            ]

        self.start = Event()
        self.thread = Thread(target=self.update)
        self.start.set()
        self.thread.start()

    def get_order(self):
        if self.orders:
            return self.orders[-1]
        else:
            return []

    def set_orders(self, orders):
        pass

    def update(self):
        while self.start.is_set():
            db_connection = connect(self.path)
            db_cursor = db_connection.cursor()
            self.orders = []
            orders = db_cursor.execute("SELECT * FROM 'order'").fetchall()
            current_time = datetime.now()
            allowed_grades = tuple()
            for i, el in enumerate(self.timetable):
                time, classes = el
                if current_time.hour == time[0] and current_time.minute < 56:
                    allowed_grades = self.timetable[i][1]

            for order in orders:
                grade = db_cursor.execute(f"SELECT grade FROM 'user' WHERE id = {order[1]}").fetchone()[0]
                state = order[2]

                if grade.isnumeric():
                    grade = int(grade)
                else:
                    grade = int(grade[:-1])

                if grade in allowed_grades and state == "active":
                    self.orders.append(order)

            db_connection.close()
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
