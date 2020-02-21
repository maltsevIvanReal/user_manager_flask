from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgres://postgres:***************************@localhost:5432/py_db'
app.config['SECRET_KEY'] = "Hello"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = '/login'
login_manager.init_app(app)
