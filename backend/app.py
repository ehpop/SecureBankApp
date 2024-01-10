import flask
from flask import Flask, session, redirect, url_for, request, jsonify
from config import Config
from flask_sqlalchemy import SQLAlchemy
from helpers.generate_numbers import generate_account_number, generate_card_number
import bcrypt, secrets
import time

REGISTER_TIMEOUT = 5
LOGIN_TIMEOUT = 5

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy()
db.init_app(app)


class Users(db.Model):
    us_nme = db.Column(db.String, nullable=False)
    us_hsh = db.Column(db.String, nullable=False)
    us_lgn = db.Column(db.String, primary_key=True)
    us_act_nb = db.Column(db.String, unique=True, nullable=False)
    us_crd_nb = db.Column(db.String, unique=True, nullable=False)
    us_blnc = db.Column(db.Integer, nullable=False)
    salt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))

    def __repr__(self):
        return f"<User {self.us_lgn}>"

    def __str__(self):
        return f"name: {self.us_nme}, login: {self.us_lgn}, account number: {self.us_act_nb}, card number: {self.us_crd_nb}, balance: {self.us_blnc}"

    def to_dict(self):
        return {
            "name": self.us_nme,
            "login": self.us_lgn,
            "account_number": self.us_act_nb,
            "card_number": self.us_crd_nb,
            "balance": self.us_blnc,
            "salt_id": self.salt_id
        }

    def to_json(self):
        return f"""{{
            "name": {self.us_nme},
            "login": {self.us_lgn},
            "account_number": {self.us_act_nb},
            "card_number": {self.us_crd_nb},
            "balance": {self.us_blnc},
            "salt_id": {self.salt_id}
        }}"""

    @staticmethod
    def get_user_by_login(login: str):
        return Users.query.where(Users.us_lgn == login).first()

    @staticmethod
    def check_password_for_user(login: str, password: str):
        user = Users.get_user_by_login(login)
        users_password_hashed = bytes.fromhex(user.us_hsh)

        return bcrypt.checkpw(password.encode("utf-8"), users_password_hashed)

    @staticmethod
    def is_login_taken(login: str):
        return Users.query.where(Users.us_lgn == login).count() > 0

    @staticmethod
    def is_account_number_taken(account_number: str):
        return Users.query.where(Users.us_act_nb == account_number).count() > 0

    @staticmethod
    def is_card_number_taken(card_number: str):
        return Users.query.where(Users.us_crd_nb == card_number).count() > 0

    @staticmethod
    def generate_new_account_number():
        acct_number = generate_account_number()
        is_acct_number_taken = Users.is_account_number_taken(acct_number)

        while is_acct_number_taken:
            acct_number = generate_account_number()
            is_acct_number_taken = Users.is_account_number_taken(acct_number)

        return acct_number

    @staticmethod
    def generate_new_card_number():
        card_number = generate_card_number()
        is_card_number_taken = Users.is_card_number_taken(card_number)

        while is_card_number_taken:
            card_number = generate_card_number()
            is_card_number_taken = Users.is_card_number_taken(card_number)

        return card_number

    def save_user(self):
        db.session.add(self)
        db.session.commit()


class UserCredentials(db.Model):
    cmb_id = db.Column(db.Integer, primary_key=True)
    usr_id = db.Column(db.String, nullable=False)
    pswd_ltrs_nmbrs = db.Column(db.String, nullable=False)
    hsh_val = db.Column(db.String, nullable=False)
    slt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))

    def __repr__(self):
        return f"<UserCredentials {self.cmb_id}>"

    def __str__(self):
        return f"user id: {self.usr_id}, password: {self.pswd_ltrs_nmbrs}, hash value: {self.hsh_val}"

    def to_dict(self):
        return {
            "user_id": self.usr_id,
            "password": self.pswd_ltrs_nmbrs,
            "hash_value": self.hsh_val
        }

    def to_json(self):
        return f"""{{
            "user_id": {self.usr_id},
            "password": {self.pswd_ltrs_nmbrs},
            "hash_value": {self.hsh_val}
        }}"""

    def save_user_credentials(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_user_credentials_by_id(user_id: str):
        return UserCredentials.query.where(UserCredentials.usr_id == user_id).first()


class Salts(db.Model):
    slt_id = db.Column(db.Integer, primary_key=True)
    slt_vl = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"<Salt {self.slt_id}>"

    def __str__(self):
        return f"salt value: {self.slt_vl} (id: {self.slt_id})"

    def to_dict(self):
        return {
            "id": self.slt_id,
            "value": self.slt_vl
        }

    def to_json(self):
        return f"""{{
            "id": {self.slt_id},
            "value": {self.slt_vl}
        }}"""

    def save_salt(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_salt_by_id(salt_id: int):
        return Salts.query.where(Salts.slt_id == salt_id).first()


class Transactions(db.Model):
    trns_id = db.Column(db.Integer, primary_key=True)
    act_frm = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    act_to = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    trns_amt = db.Column(db.Integer, nullable=False)
    trns_dt = db.Column(db.String, nullable=False)
    trns_ttl = db.Column(db.String, nullable=False)


class Documents(db.Model):
    dcm_id = db.Column(db.Integer, primary_key=True)
    dcm_cnt = db.Column(db.String, nullable=False)
    dcm_sze = db.Column(db.Integer, nullable=False)
    dcm_ad_dt = db.Column(db.String, nullable=False)
    dcm_ttl = db.Column(db.String, nullable=False)
    own_id = db.Column(db.String, db.ForeignKey("users.us_lgn"))


@app.route("/health")
def health():
    return f"<h1>Healthy</h1>"


@app.route("/session")
def session_info():
    return f"<h1>{session}</h1>"

@app.route("/test")
def test():
    return flask.render_template("test.html")

@app.route("/my_account_number")
def my_account_number():
    if "user_id" not in session or "authenticated" not in session or not session["authenticated"]:
        return jsonify({"error": "Unauthorized"}), 401

    user = Users.get_user_by_login(session["user_id"])

    return jsonify({"account_number": user.us_act_nb}), 200


@app.route("/register", methods=["POST"])
def register_user():
    username = request.json["username"]
    password = request.json["password"]
    name = request.json["name"]
    lastname = request.json["lastname"]

    if Users.is_login_taken(username):
        app.logger.info(Users.get_user_by_login(username))
        time.sleep(REGISTER_TIMEOUT)
        return jsonify({"error": "Username already taken"}), 409

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    app.logger.info(new_salt.to_json())

    new_user = Users(us_nme=f"{name} {lastname}", us_hsh=hashed_password, us_lgn=username,
                     us_act_nb=Users.generate_new_account_number(), us_crd_nb=Users.generate_new_card_number(),
                     us_blnc=0, salt_id=new_salt.slt_id)

    new_user.save_user()

    app.logger.info(new_user.to_json())
    time.sleep(REGISTER_TIMEOUT)

    return new_user.to_json(), 201


@app.route("/logout_success", methods=["GET"])
def logout_success():
    return f"<h1>Logout successful</h1>"

@app.route("/logout", methods=["POST"])
def logout_user():
    session.pop("user_id", None)
    session.pop("authenticated", None)
    return redirect(url_for("logout_success", _method="GET"))


@app.route("/login", methods=["POST"])
def login_user():
    username = request.json["username"]
    password = request.json["password"]

    if not Users.check_password_for_user(username, password):
        time.sleep(LOGIN_TIMEOUT)
        return jsonify({"error": "Unauthorized"}), 401

    session["user_id"] = username
    session["authenticated"] = True

    time.sleep(LOGIN_TIMEOUT)
    return jsonify({"message": "Successfully logged in"}), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
