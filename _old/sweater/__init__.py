from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, set_login_view


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.secret_key = "88bd9b3b7c8591ca71cc5ca1ec1e55f6e61ead6c9051c1eabb93e0b1021b996a"
db = SQLAlchemy(app)
login_manager = LoginManager(app)


from sweater.models import Queue
queue = Queue(None)
from sweater import routes, models


#app.register_error_handler(routes.internal_server_error())
with app.app_context():
    db.create_all()
    set_login_view("login_page")
