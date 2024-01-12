import io
import os

import flask
from flask import Flask, session, redirect, url_for, request, jsonify
from config import Config
from flask_sqlalchemy import SQLAlchemy
from helpers.generate_numbers import generate_account_number, generate_card_number, generate_random_consecutive_numbers
from helpers.password_checker import check_password_strength
from datetime import datetime, timedelta
from helpers.auth_wrapper import requires_authentication
from helpers.file_content_checker import check_file_content_based_on_extension, get_file_extension
from helpers.file_encrypter import encrypt_file_content_with_key, decrypt_file_content_with_key
from werkzeug.utils import secure_filename
import pyAesCrypt
import bcrypt, secrets, time

MAX_FAILED_LOGIN_ATTEMPTS = 3

AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD = 6

REGISTER_TIMEOUT = 2
LOGIN_TIMEOUT = 2

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
            "name": "{self.us_nme}",
            "login": "{self.us_lgn}",
            "account_number": "{self.us_act_nb}",
            "card_number": "{self.us_crd_nb}",
            "balance": "{self.us_blnc}",
            "salt_id": "{self.salt_id}"
        }}"""

    @staticmethod
    def get_user_by_login(login: str):
        return Users.query.where(Users.us_lgn == login).first()

    @staticmethod
    def get_user_by_account(account_number: str):
        return Users.query.where(Users.us_act_nb == account_number).first()

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

    def remove_user(self):
        db.session.delete(self)
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
            "user_id": "{self.usr_id}",
            "password": "{self.pswd_ltrs_nmbrs}",
            "hash_value": "{self.hsh_val}"
        }}"""

    def save_user_credentials(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_user_credentials_by_user_id(user_id: str):
        return UserCredentials.query.where(UserCredentials.usr_id == user_id).first()

    @staticmethod
    def get_user_credentials_by_id(combination_id: str):
        return UserCredentials.query.where(UserCredentials.cmb_id == combination_id).first()

    @staticmethod
    def check_password_combination_for_id(combination_id: str, password: str):
        combination = UserCredentials.get_user_credentials_by_id(combination_id)

        if combination is None:
            return False

        return bcrypt.checkpw(password.encode("utf-8"), bytes.fromhex(combination.hsh_val))

    @staticmethod
    def get_random_credentials_for_user(user_id: str):
        all_user_credentials = UserCredentials.query.where(UserCredentials.usr_id == user_id).all()
        random_credentials = secrets.choice(all_user_credentials)
        return random_credentials

    @staticmethod
    def parse_list_of_numbers_from_string(string: str) -> list[int]:
        return [int(number) for number in string.lstrip("{").rstrip("}").split(",")]


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

    def remove_salt(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_salt_by_id(salt_id: int):
        return Salts.query.where(Salts.slt_id == salt_id).first()


class Transactions(db.Model):
    trns_id = db.Column(db.Integer, primary_key=True)
    act_frm = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    act_to = db.Column(db.String, db.ForeignKey("users.us_act_nb"))
    trns_amt = db.Column(db.Integer, nullable=False)
    trns_dt = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    trns_ttl = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"<Transactions {self.trns_id}>"

    def __str__(self):
        return f"from: {self.act_frm}, to: {self.act_to}, amount: {self.trns_amt}, date: {self.trns_dt}, title: {self.trns_ttl}"

    def to_dict(self):
        return {
            "from": self.act_frm,
            "to": self.act_to,
            "amount": self.trns_amt,
            "date": self.trns_dt,
            "title": self.trns_ttl
        }

    def to_json(self):
        return f"""{{
            "from": "{self.act_frm}",
            "to": "{self.act_to}",
            "amount": "{self.trns_amt}",
            "date": "{self.trns_dt}",
            "title": "{self.trns_ttl}"
        }}"""

    def save_transaction(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_all_transactions():
        return Transactions.query.where(1 == 1).all()

    @staticmethod
    def get_transactions_by_account_number(account_number: str):
        app.logger.info(account_number)

        app.logger.info(Transactions.query.where(
            Transactions.act_frm == account_number or Transactions.act_to == account_number).all()
                        )

        return Transactions.query.where(
            Transactions.act_frm == account_number or Transactions.act_to == account_number).all()

    @staticmethod
    def get_transactions_by_account_number_and_date(account_number: str, date: str):
        return Transactions.query.where(
            Transactions.act_frm == account_number or Transactions.act_to == account_number).where(
            Transactions.trns_dt == date).all()

    @staticmethod
    def get_transactions_made_by_user(user_login: str) -> list:
        user = Users.query.where(Users.us_lgn == user_login).first()
        app.logger.info(f"User for whom transactions are being fetched: {user} ")

        if user is None:
            return []

        return Transactions.get_transactions_by_account_number(user.us_act_nb)

    @staticmethod
    def get_transactions_incoming_to_user(user_login: str) -> list:
        user = Users.query.where(Users.us_lgn == user_login).first()

        if user is None:
            return []

        return Transactions.query.where(Transactions.act_to == user.us_act_nb).all()

    @staticmethod
    def get_transactions_outgoing_from_user(user_login: str) -> list:
        user = Users.query.where(Users.us_lgn == user_login).first()
        app.logger.info(f"User for whom transactions are being fetched: {user} ")

        if user is None:
            return []

        return Transactions.query.where(Transactions.act_frm == user.us_act_nb).all()


class Documents(db.Model):
    dcm_id = db.Column(db.Integer, primary_key=True)
    dcm_cnt = db.Column(db.String, nullable=False)
    dcm_sze = db.Column(db.Integer, nullable=False)
    dcm_ad_dt = db.Column(db.String, nullable=False)
    dcm_ttl = db.Column(db.String, nullable=False)
    own_id = db.Column(db.String, db.ForeignKey("users.us_lgn"))


class LoginAttempts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, db.ForeignKey("users.us_lgn"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String, nullable=False)
    success = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"<LoginAttempt {self.id}>"

    def __str__(self):
        return f"username: {self.username}, timestamp: {self.timestamp}, ip_address: {self.ip_address}, success: {self.success}"

    def to_dict(self):
        return {
            "username": self.username,
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "success": self.success
        }

    def to_json(self):
        return f"""{{
            "username": "{self.username}",
            "timestamp": "{self.timestamp}",
            "ip_address": "{self.ip_address}",
            "success": "{self.success}"
        }}"""

    def save_login_attempt(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def calculate_failed_login_attempts_in_period(username: str, ip_address: str, period_of_time=10) -> int:
        """
        Calculates the amount of failed login attempts in a given period of time.
        :param username: username of the user that is trying to log in
        :param ip_address: ip address of the user that is trying to log in
        :param period_of_time: period of time in minutes, default is 10
        :return: amount of failed login attempts in a given period of time
        """

        failed_login_attempts = (LoginAttempts.query
        .where(LoginAttempts.username == username)
        .where(LoginAttempts.ip_address == ip_address)
        .where(LoginAttempts.success == False)
        .where(
            LoginAttempts.timestamp > datetime.utcnow() - timedelta(minutes=period_of_time)))

        return failed_login_attempts.count()

    @staticmethod
    def get_all_ip_addresses_for_user(username: str) -> list[dict]:
        """
        Gets all IP addresses that were used to log in to a given account.
        :param username: username of the user
        :return: list of IP addresses
        """
        return [{"ip_address": login_attempt.ip_address, "timestamp": login_attempt.timestamp} for login_attempt in
                LoginAttempts.query.where(LoginAttempts.username == username).all()]

    @staticmethod
    def get_all_login_attempts_for_user(username: str) -> list[dict]:
        """
        Gets all login attempts for a given user.
        :param username: username of the user
        :return: list of login attempts
        """
        return [{"ip_address": login_attempt.ip_address, "timestamp": login_attempt.timestamp,
                 "success": login_attempt.success} for login_attempt in
                LoginAttempts.query.where(LoginAttempts.username == username).all()]

    @staticmethod
    def get_all_failed_login_attempts_for_user(username: str) -> list[dict]:
        """
        Gets all failed login attempts for a given user.
        :param username: username of the user
        :return: list of failed login attempts
        """
        return [{"ip_address": login_attempt.ip_address, "timestamp": login_attempt.timestamp,
                 "success": login_attempt.success} for login_attempt in
                LoginAttempts.get_all_login_attempts_for_user(username) if not login_attempt["success"]]

    @staticmethod
    def get_all_successful_login_attempts_for_user(username: str) -> list[dict]:
        """
        Gets all successful login attempts for a given user.
        :param username: username of the user
        :return: list of successful login attempts
        """
        return [{"ip_address": login_attempt.ip_address, "timestamp": login_attempt.timestamp,
                 "success": login_attempt.success} for login_attempt in
                LoginAttempts.get_all_login_attempts_for_user(username) if login_attempt["success"]]


@app.route("/health")
def health():
    return f"<h1>Healthy</h1>"


@app.route("/session")
def session_info():
    return f"<h1>{session}</h1>"


@app.route("/test", methods=["GET", "POST"])
def test():
    return flask.render_template("test.html")


@app.route("/register", methods=["POST"])
def register_user():
    time.sleep(REGISTER_TIMEOUT)

    app.logger.info(f"Request coming from IP: {request.remote_addr}")
    username = request.json["username"]
    password = request.json["password"]
    name = request.json["name"]
    lastname = request.json["lastname"]

    if not username and not password and not name and not lastname:
        return jsonify({"error": "Missing data"}), 409

    if Users.is_login_taken(username):
        app.logger.info(Users.get_user_by_login(username))
        return jsonify({"error": "Username already taken"}), 400

    password_strength_errors = check_password_strength(password)
    if password_strength_errors:
        return password_strength_errors, 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    app.logger.info(new_salt.to_json())
    new_user = Users(us_nme=f"{name} {lastname}", us_hsh=hashed_password, us_lgn=username,
                     us_act_nb=Users.generate_new_account_number(), us_crd_nb=Users.generate_new_card_number(),
                     us_blnc=0, salt_id=new_salt.slt_id)

    new_user.save_user()
    generated_combinations = []
    for _ in range(10):
        combination_of_password_letters = generate_random_consecutive_numbers(len(password),
                                                                              AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD)

        while combination_of_password_letters in generated_combinations:
            combination_of_password_letters = generate_random_consecutive_numbers(len(password),
                                                                                  AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD)

        letters_in_password = "".join([password[i - 1] for i in combination_of_password_letters])
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(letters_in_password.encode("utf-8"), salt).hex()

        new_salt = Salts(slt_vl=salt.hex())
        new_salt.save_salt()

        user_credentials = UserCredentials(usr_id=username, pswd_ltrs_nmbrs=combination_of_password_letters,
                                           hsh_val=hashed_password, slt_id=new_salt.slt_id)
        user_credentials.save_user_credentials()

    return redirect(url_for('register_success', _method="GET"))


@app.route("/", methods=["GET"])
def index():
    return flask.render_template("index.html")

@app.route("/logout_success", methods=["GET"])
def logout_success():
    return f"<h1>Logout successful</h1>"


@app.route("/register/success", methods=["GET"])
def register_success():
    return f"<h1>Registration successful</h1>"


@app.route("/logout", methods=["POST"])
def logout_user():
    session.pop("username", None)
    session.pop("user_id", None)
    session.pop("authenticated", None)
    return redirect(url_for("logout_success", _method="GET"))


@app.route("/get_password_combination/<user_id>")
def get_password_combination(user_id: str):
    credentials = UserCredentials.get_random_credentials_for_user(user_id)
    return jsonify({
        "combination_id": credentials.cmb_id,
        "letters_combination": credentials.pswd_ltrs_nmbrs
    }), 200


@app.route("/login", methods=["POST"])
def login_user():
    time.sleep(LOGIN_TIMEOUT)

    try:
        username = request.json["username"]
        password = request.json["password"]
        combination_id = request.json["combination_id"]
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    login_attempt = LoginAttempts(username=username, ip_address=request.remote_addr)

    if LoginAttempts.calculate_failed_login_attempts_in_period(username,
                                                               request.remote_addr) >= MAX_FAILED_LOGIN_ATTEMPTS:
        return jsonify({"error": "Too many login attempts"}), 429

    if not UserCredentials.check_password_combination_for_id(combination_id, password):
        login_attempt.success = False
        login_attempt.save_login_attempt()
        return jsonify({"error": "Wrong credentials"}), 401

    session["user_id"] = username
    session["authenticated"] = True

    login_attempt.success = True
    login_attempt.save_login_attempt()

    return redirect(url_for("login_success", _method="GET")), 302

@app.route("/login/success", methods=["GET"])
def login_success():
    return f"<h1>Login successful</h1>"


@app.route("/transfer_money", methods=["POST"])
@requires_authentication
def transfer_money():
    user = Users.get_user_by_login(session["user_id"])
    amount = request.json["amount"]
    recipient_account_number = request.json["recipient_account_number"]
    transfer_title = request.json["transfer_title"]
    recipient_user = Users.get_user_by_account(recipient_account_number)

    if recipient_user is None:
        return jsonify({"error": "Recipient does not exist"}), 404

    if user.us_blnc < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    user.us_blnc -= amount
    recipient_user.us_blnc += amount

    transaction = Transactions(act_frm=user.us_act_nb, act_to=recipient_user.us_act_nb, trns_amt=amount,
                               trns_dt=datetime.utcnow(), trns_ttl=transfer_title)
    transaction.save_transaction()

    return jsonify({"message": "Transfer successful"}), 200


@app.route("/get_transactions", methods=["GET"])
@requires_authentication
def get_transactions():
    user = Users.get_user_by_login(session["user_id"])
    transactions = Transactions.get_transactions_by_account_number(user.us_act_nb)

    return jsonify([transaction.to_dict() for transaction in transactions]), 200


@app.route("/get_transactions_out", methods=["GET"])
@requires_authentication
def get_transactions_outgoing():
    user = Users.get_user_by_login(session["user_id"])
    transactions = Transactions.get_transactions_outgoing_from_user(user.us_lgn)

    return jsonify([transaction.to_dict() for transaction in transactions]), 200


@app.route("/get_transactions_in", methods=["GET"])
@requires_authentication
def get_transactions_incoming():
    user = Users.get_user_by_login(session["user_id"])
    transactions = Transactions.get_transactions_incoming_to_user(user.us_lgn)

    return jsonify([transaction.to_dict() for transaction in transactions]), 200


@app.route("/get_all_login_attemps")
@requires_authentication
def get_all_login_attempts():
    user = Users.get_user_by_login(session["user_id"])
    login_attempts = LoginAttempts.get_all_login_attempts_for_user(user.us_lgn)

    return jsonify(login_attempts), 200


@app.route('/send_document', methods=['GET'])
@requires_authentication
def post_form():
    return flask.render_template('post_form.html')


@app.route('/send_document', methods=['POST'])
@requires_authentication
def send_document():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    try:
        password = request.form['password']
        uploaded_file = request.files['file']
        user_id = session['user_id']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    uploaded_file_content = uploaded_file.stream.read()
    uploaded_file_name = secure_filename(uploaded_file.filename)

    if not password or not user_id:
        return jsonify({"error": "Unauthorized request"}), 401

    passw = password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return jsonify({"error": "Wrong credentials"}), 401

    file_extension = get_file_extension(uploaded_file_name)

    if not file_extension in app.config['UPLOAD_EXTENSIONS']:
        return jsonify({"error": "Invalid file extension"}), 400

    if not check_file_content_based_on_extension(uploaded_file.stream, file_extension):
        return jsonify({"error": "Invalid file content"}), 400

    user_custom_path = os.path.join(app.config['UPLOAD_PATH'], user_id)
    if not os.path.exists(user_custom_path):
        os.makedirs(user_custom_path)

    salt = bytes.fromhex(Salts.get_salt_by_id(Users.get_user_by_login(user_id).salt_id).slt_vl)
    file_encrypted = encrypt_file_content_with_key(uploaded_file_content, password, salt)

    with open(os.path.join(user_custom_path, uploaded_file_name + '.aes'), "wb") as f:
        f.write(file_encrypted)

    return jsonify({"message": "File uploaded successfully"}), 200


@app.route('/get_document', methods=['GET'])
@requires_authentication
def get_form():
    return flask.render_template('get_form.html')


@app.route('/get_document', methods=['POST'])
@requires_authentication
def get_document():
    try:
        password = request.form['password']
        filename = request.form['filename']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    user_id = session['user_id']
    is_authenticated = session['authenticated']

    if not is_authenticated or not user_id:
        return jsonify({"error": "Unauthorized request"}), 401

    passw = password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return jsonify({"error": "Wrong credentials"}), 401

    user_custom_path = os.path.join(app.config['UPLOAD_PATH'], user_id)

    try:
        with open(os.path.join(user_custom_path, filename + '.aes'), "rb") as f:
            content = f.read()
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 400

    if not content:
        return jsonify({"error": "No file found"}), 400

    salt = bytes.fromhex(Salts.get_salt_by_id(Users.get_user_by_login(user_id).salt_id).slt_vl)
    decrypted_data = decrypt_file_content_with_key(content, password, salt)

    return flask.send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=filename)


@app.route('/get_document_without_encryption', methods=['GET'])
def get_document_without_encryption():
    filename = "swiadectwo.png"
    return flask.send_file(filename, as_attachment=True, download_name=filename)


@app.route('/get_all_document_names', methods=['POST'])
def get_all_document_names():
    try:
        password = request.form['password']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    user_id = session['user_id']
    is_authenticated = session['authenticated']

    if not is_authenticated or not user_id:
        return jsonify({"error": "Unauthorized request"}), 401

    passw = password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return jsonify({"error": "Wrong credentials"}), 401

    user_custom_path = os.path.join(app.config['UPLOAD_PATH'], user_id)

    try:
        filenames = [filename[:-4] for filename in os.listdir(user_custom_path) if filename.endswith(".aes")]
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 400

    if not filenames:
        return jsonify({"error": "No files found"}), 400

    return jsonify(filenames), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
