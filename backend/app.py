from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from database import db
from helpers.user_helper import UserHelper
from database import Users

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


@app.route("/health")
def health():
    return "<h1>Healthy</h1>"


@app.route("/test")
def test():
    user_helper = UserHelper()
    result = ""
    for user in user_helper.get_all_users():
        result += f"<p>User: {user.us_nme}, {user.us_lgn}</p>"
    return result


@app.get("/users/<username>")
def get_user(username):
    if username not in UserHelper().get_all_usernames():
        return f"<p>User {username} not found</p>"
    user_helper = UserHelper()
    user = user_helper.get_user(username)
    return f"<p>User: {user.us_nme}, {user.us_lgn}</p>"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
