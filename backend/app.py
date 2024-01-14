import io
import os
import time
from datetime import datetime

import PIL
import bcrypt
import flask
from flask import Flask, session, redirect, url_for, request, jsonify
from werkzeug.utils import secure_filename

from config import Config
from helpers.auth_wrapper import requires_authentication
from helpers.file_content_checker import check_file_content_based_on_extension, get_file_extension
from helpers.file_encrypter import encrypt_file_content_with_key, decrypt_file_content_with_key
from helpers.generate_numbers import generate_card_data
from helpers.password_checker import check_password_strength
from helpers.string_ecrypter import encrypt_string_with_password
from models import db

app = Flask(__name__)
app.config.from_object(Config)
app.app_context().push()

db.init_app(app)
logger = app.logger

from models import Users, Salts, UserCredentials, Transactions, LoginAttempts, CreditCards, Documents

with app.app_context():
    db.create_all()
    PIL.Image.MAX_IMAGE_PIXELS = app.config['MAX_PIL_IMAGE_PIXELS']


@app.route("/health")
def health():
    return f"<h1>Healthy</h1>"


@app.route("/unauthorized", methods=["GET"])
def unauthorized():
    return flask.render_template("unauthorized.html")

@app.route("/test", methods=["GET", "POST"])
def test():
    return flask.render_template("test.html")


@app.route("/register", methods=["GET"])
def register():
    return flask.render_template("register.html")

@app.route("/register", methods=["POST"])
def register_user():
    time.sleep(app.config['REGISTER_TIMEOUT'])

    try:
        username = request.json["username"]
        password = request.json["password"]
        email = request.json["email"]
        name = request.json["name"]
        lastname = request.json["lastname"]
    except KeyError:
        return jsonify({"error": "Missing data"}), 409

    # TODO: Sanitize input

    if Users.is_login_taken(username):
        logger.info(Users.get_user_by_login(username))
        return jsonify({"error": "Username already taken"}), 400

    password_strength_errors = check_password_strength(password)
    if password_strength_errors:
        return password_strength_errors, 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()
    logger.info(new_salt.to_json())

    new_card_details, hidden_card_details = generate_card_data()

    credit_card = CreditCards(crd_nb_hidden=hidden_card_details['card_number'],
                              crd_cvc_hidden=hidden_card_details['cvc'],
                              crd_exp_dt_hidden=hidden_card_details['expiry_date'],
                              crd_nb=encrypt_string_with_password(new_card_details['card_number'], password, salt),
                              crd_cvc=encrypt_string_with_password(new_card_details['cvc'], password, salt),
                              crd_exp_dt=encrypt_string_with_password(new_card_details['expiry_date'], password, salt),
                              slt_id=new_salt.slt_id)

    credit_card.save_credit_card()

    new_user = Users(
        us_lgn=username,
        us_email=email,
        us_nme=f"{name} {lastname}",
        us_hsh=hashed_password,
        us_act_nb=Users.generate_new_account_number(),
        us_crd_nb_id=credit_card.crd_id,
        us_blnc=0,
        salt_id=new_salt.slt_id)

    new_user.save_user()

    UserCredentials.generate_new_password_combinations(password,
                                                       new_user.us_lgn,
                                                       app.config['AMOUNT_OF_COMBINATIONS_GENERATED_FOR_PASSWORD'],
                                                       app.config['AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD'])

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
    session.pop("user_id", None)
    session.pop("authenticated", None)
    return redirect(url_for("logout_success", _method="GET"))


@app.route("/get_password_combination/<user_id>")
def get_password_combination(user_id: str):
    credentials = UserCredentials.get_random_credentials_for_user(user_id)

    if credentials is None:
        return jsonify({"error": "No credentials found"}), 404

    return jsonify({
        "combination_id": credentials.cmb_id,
        "letters_combination": credentials.pswd_ltrs_nmbrs
    }), 200


@app.route("/login", methods=["GET"])
def login():
    return flask.render_template("login.html")

@app.route("/login", methods=["POST"])
def login_user():
    time.sleep(app.config['LOGIN_TIMEOUT'])

    try:
        username = request.json["username"]
        password = request.json["password"]
        combination_id = request.json["combination_id"]
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    user = Users.get_user_by_login(username)
    if user is None:
        return jsonify({"error": "Wrong credentials"}), 401

    login_attempt = LoginAttempts(username=username, ip_address=request.remote_addr, success=False)

    if LoginAttempts.calculate_failed_login_attempts_in_period(username,
                                                               request.remote_addr) >= app.config[
        'MAX_FAILED_LOGIN_ATTEMPTS']:
        login_attempt.save_login_attempt()
        return jsonify({"error": "Too many login attempts"}), 429

    if not UserCredentials.check_password_combination_for_id(combination_id, password):
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
    try:
        user = Users.get_user_by_login(session["user_id"])
        amount = request.json["amount"]
        recipient_account_number = request.json["recipient_account_number"]
        transfer_title = request.json["transfer_title"]
        recipient_user = Users.get_user_by_account(recipient_account_number)
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    try:
        Transactions.make_transaction(user.us_act_nb, recipient_account_number, amount, transfer_title)
    except ValueError as e:
        return jsonify({"error": f"Transfer failed, reason: {str(e)}"}), 400

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

    errors = check_password_strength(password)
    if errors:
        return jsonify(errors), 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()
    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

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

    document = Documents(own_id=user_id,
                         dcm_ttl=uploaded_file_name,
                         dcm_typ=file_extension,
                         dcm_hsh=hashed_password,
                         dcm_slt_id=new_salt.slt_id,
                         dcm_ad_dt=datetime.utcnow())

    document.save_document()

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

    document = Documents.get_document_for_user_by_filename(user_id, filename)

    if document is None:
        return jsonify({"error": "File not found"}), 400

    filename = document.dcm_ttl
    passw = password.encode("utf-8")
    hashed_password = bytes.fromhex(document.dcm_hsh)

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


@app.route('/change_password', methods=['GET'])
@requires_authentication
def change_password():
    return flask.render_template('change_password_form.html')


@app.route('/change_password', methods=['POST'])
@requires_authentication
def change_password_post():
    time.sleep(app.config['CHANGE_PASSWORD_TIMEOUT'])

    try:
        old_password = request.form['old_password']
        new_password = request.form['new_password']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    user_id = session['user_id']
    is_authenticated = session['authenticated']

    if not is_authenticated or not user_id:
        return jsonify({"error": "Unauthorized request"}), 401

    passw = old_password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return jsonify({"error": "Wrong credentials"}), 401

    new_password_hashed_with_old_salt = bcrypt.hashpw(new_password.encode("utf-8"),
                                                      bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)).hex()
    if new_password_hashed_with_old_salt == Users.get_user_by_login(user_id).us_hsh:
        return jsonify({"error": "New password cannot be the same as old password"}), 400

    password_strength_errors = check_password_strength(new_password)
    if password_strength_errors:
        return password_strength_errors, 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    try:
        Users.update_user_password(user_id, new_password, hashed_password, new_salt.slt_id)
    except ValueError:
        return jsonify({"error": "Password could not be changed"}), 400

    return jsonify({"message": "Password changed successfully"}), 200
