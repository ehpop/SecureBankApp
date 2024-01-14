import io
import os
import time

import bcrypt
import flask
from PIL.Image import Image
from flask import Flask, session, redirect, url_for, request, jsonify

from config import Config
from helpers.auth_wrapper import requires_authentication
from helpers.password_checker import check_password_strength
from models import db
from views_helper import check_if_password_is_same_as_previous, hash_new_password_with_new_salt, \
    check_if_user_provided_correct_password, verify_provided_password_recovery_code

app = Flask(__name__)
app.config.from_object(Config)
app.app_context().push()

db.init_app(app)
logger = app.logger

from models import Users, Salts, UserCredentials, Transactions, LoginAttempts, CreditCards, Documents, \
    PasswordRecoveryCodes

with app.app_context():
    db.create_all()
    Image.MAX_IMAGE_PIXELS = app.config['MAX_PIL_IMAGE_PIXELS']


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
        return jsonify({"error": "Username already taken"}), 400

    password_strength_errors = check_password_strength(password)
    if password_strength_errors:
        return password_strength_errors, 400

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    credit_card = CreditCards.generate_new_encrypted_credit_card_with_password_and_salt(password,
                                                                                        new_salt,
                                                                                        new_salt.slt_id)

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
        ip_address = request.remote_addr
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    try:
        user = Users.login_user(username, password, ip_address, combination_id, app.config['MAX_FAILED_LOGIN_ATTEMPTS'])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    session["user_id"] = user.us_lgn
    session["authenticated"] = True

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
        password = request.json["password"]
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    response = check_if_user_provided_correct_password(session, password)
    if response:
        return response

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

    try:
        document = Documents.save_encrypted_document(user_id,
                                                     password,
                                                     uploaded_file,
                                                     app.config['UPLOAD_EXTENSIONS'],
                                                     app.config['UPLOAD_PATH'])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"message": f"File {document.dcm_ttl} uploaded successfully"}), 200


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

    try:
        decrypted_data = Documents.read_encrypted_document(user_id, filename, password, app.config['UPLOAD_PATH'])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return flask.send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=filename)


@app.route('/delete_document', methods=['POST'])
@requires_authentication
def delete_document():
    try:
        password = request.form['password']
        filename = request.form['filename']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    user_id = session['user_id']

    try:
        Documents.delete_encrypted_document_from_server(user_id, filename, password, app.config['UPLOAD_PATH'])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"message": f"File {filename} deleted successfully"}), 200


@app.route('/get_all_document_names', methods=['POST'])
@requires_authentication
def get_all_document_names():
    try:
        password = request.form['password']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    response = check_if_user_provided_correct_password(session, password)
    if response:
        return response

    user_id = session['user_id']
    user_custom_path = os.path.join(app.config['UPLOAD_PATH'], user_id)

    try:
        filenames = [filename[:-4] for filename in os.listdir(user_custom_path) if filename.endswith(".aes")]
    except FileNotFoundError:
        filenames = []

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

    response = check_if_user_provided_correct_password(session, old_password)
    if response:
        return response

    is_password_same = check_if_password_is_same_as_previous(new_password, user_id)
    if is_password_same:
        return is_password_same

    password_strength_errors = check_password_strength(new_password)
    if password_strength_errors:
        return password_strength_errors, 400

    new_salt, hashed_password = hash_new_password_with_new_salt(new_password)

    try:
        Users.update_user_password(user_id, new_password, hashed_password, new_salt.slt_vl, new_salt.slt_id)
    except ValueError:
        return jsonify({"error": "Password could not be changed"}), 400

    return jsonify({"message": "Password changed successfully"}), 200


@app.route('/password_recovery', methods=['GET'])
def password_recovery():
    return flask.render_template('password_recovery_form.html')


@app.route('/password_recovery', methods=['POST'])
def password_recovery_post():
    time.sleep(app.config['PASSWORD_RECOVERY_TIMEOUT'])

    try:
        email = request.form['email']
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    try:
        code = PasswordRecoveryCodes.generate_new_unique_password_recovery_code_for_user(email)
        PasswordRecoveryCodes.send_password_recovery_code(email, code, app.logger)
    except ValueError:
        return jsonify({"error": "Recovery code could not be send"}), 400

    return jsonify({
        "message": f"Recovery code send successfully to email {email}. "
                   f"Code is active for {app.config['TIME_ALLOWED_FOR_PASSWORD_RECOVERY']} minute(s). "
                   f"Normally you would have to get it from there, but hey, u seam like trustworthy user, so "
                   f"just for u here it is: {flask.url_for('password_recovery_verify', password_recovery_code=code)}"}), 200


@app.route('/password_recovery/verify/<password_recovery_code>', methods=['GET'])
def password_recovery_verify(password_recovery_code: str):
    response = verify_provided_password_recovery_code(password_recovery_code)
    if response:
        return response

    return flask.render_template('password_recovery_verify_form.html')


@app.route('/password_recovery/verify/<password_recovery_code>', methods=['POST'])
def password_recovery_verify_post(password_recovery_code: str):
    time.sleep(app.config['PASSWORD_RECOVERY_TIMEOUT'])

    try:
        code_object = verify_provided_password_recovery_code(password_recovery_code)
    except ValueError as e:
        return jsonify({"error": f"{e}"}), 400

    try:
        new_password = request.form['new_password']
        user_id = code_object.user_id
    except KeyError:
        return jsonify({"error": "Missing data"}), 400

    is_password_same = check_if_password_is_same_as_previous(new_password, user_id)
    if is_password_same:
        return is_password_same

    password_strength_errors = check_password_strength(new_password)
    if password_strength_errors:
        return password_strength_errors, 400

    new_salt, hashed_password = hash_new_password_with_new_salt(new_password)

    try:
        Users.update_user_password(code_object.user_id, new_password, hashed_password, new_salt.slt_vl, new_salt.slt_id)
        code_object.delete_password_recovery_code()
    except ValueError:
        return jsonify({"error": "Password could not be changed"}), 400

    return jsonify({"message": "Password changed successfully"}), 200
