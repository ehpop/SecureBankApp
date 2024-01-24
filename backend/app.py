import io
import os
import time

import flask
from PIL.Image import Image
from flask import Flask, session, redirect, url_for, request, jsonify, flash
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db

app = Flask(__name__)
app.config.from_object(Config)
app.app_context().push()

db.init_app(app)

from views_helper import check_if_password_is_same_as_previous, hash_new_password_with_new_salt, \
    check_if_user_provided_correct_password, verify_provided_password_recovery_code

from models import Users, UserCredentials, Transactions, LoginAttempts, CreditCards, Documents, \
    PasswordRecoveryCodes
from forms.login_form import LoginForm
from forms.register_form import RegisterForm
from forms.login_with_password_form import LoginWithPasswordForm
from forms.transfer_money_form import TransferMoneyForm
from forms.send_document_form import SendDocumentForm
from forms.access_document_form import AccessDocumentForm
from forms.change_password_form import ChangePasswordForm
from forms.password_recovery_form import PasswordRecoveryCodeForm
from forms.set_new_password_form import SetNewPasswordForm
from helpers.password_checker import check_password_strength
from flask_login import LoginManager, login_user, login_required, logout_user

with app.app_context():
    db.create_all()
    Image.MAX_IMAGE_PIXELS = app.config['MAX_PIL_IMAGE_PIXELS']

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    csrf = CSRFProtect(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.get_user_by_login(user_id)


@app.before_request
def check_session_id():
    if session.get("user_id", None) is None or session.get("authenticated", None) is None:
        return

    if session.get("ip_address", None) != request.remote_addr or session.get("user_agent",
                                                                             None) != request.user_agent.string:
        session.pop("user_id", None)
        session.pop("authenticated", None)
        logout_user()
        return redirect(url_for("index"))


def create_app():
    return app


@app.route("/health")
def health():
    return jsonify({"message": "Service healthy"}), 200


@app.route("/", methods=["GET"])
def index():
    user_id = session.get("user_id", None)
    if user_id is None:
        return flask.render_template("index.html")
    card = CreditCards.get_credit_card_by_owner(user_id)
    card_data = {"number": card.crd_nb_hidden, "cvc": card.crd_cvc_hidden,
                 "expiry_date": card.crd_exp_dt_hidden}
    return flask.render_template("index.html", card_data=card_data)


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        time.sleep(app.config['REGISTER_TIMEOUT'])
        name = form.name.data
        lastname = form.lastname.data
        username = form.username.data
        email = form.email.data
        password = form.password.data
        repeat_password = form.repeat_password.data

        try:
            Users.register_user(username=username, name=name, lastname=lastname, email=email, password=password,
                                repeat_password=repeat_password)
        except ValueError as e:
            flash(str(e))
            return flask.render_template("login/register.html", form=form)
        except Users.PasswordErrorsException as e:
            for error in e.error_list:
                flash(error)
            return flask.render_template("login/register.html", form=form)

        flash("You have been registered successfully")
        return redirect(url_for("login"))
    else:
        for error in form.errors:
            flash(form.errors[error][0])
    return flask.render_template("login/register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    username = None
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        return redirect(url_for("get_password_combination", user_id=username))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("login/login.html", form=form, username=username)


@app.route("/login/<user_id>", methods=["GET", "POST"])
def get_password_combination(user_id: str):
    credentials = UserCredentials.get_random_credentials_for_user(user_id)

    if credentials is None:
        combination = UserCredentials.get_fake_credentials()[1]
        combination_id = -1
    else:
        combination = UserCredentials.parse_list_of_numbers_from_string(credentials.pswd_ltrs_nmbrs)
        combination_id = credentials.cmb_id

    form = LoginWithPasswordForm()

    if form.validate_on_submit():
        time.sleep(app.config['LOGIN_TIMEOUT'])
        password_letters = form.password.data
        ip_address = request.remote_addr
        try:
            user = Users.login_user(user_id, password_letters, ip_address, combination_id)
            session["user_id"] = user.us_lgn
            session["authenticated"] = True
            session["ip_address"] = ip_address
            session["user_agent"] = request.user_agent.string
            flash("You have been logged in successfully")
            login_user(user)

            return redirect(url_for("index", _method="GET")), 302
        except ValueError as e:
            flash(str(e))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("login/login_with_password_combination.html", form=form, username=user_id,
                                 combination=combination)


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    session.pop("user_id", None)
    session.pop("authenticated", None)
    logout_user()

    return redirect(url_for("index"))


@app.route("/transfer_money", methods=["GET", "POST"])
@login_required
def transfer_money():
    form = TransferMoneyForm()

    if form.validate_on_submit():
        transfer_recipient = form.recipient.data
        transfer_title = form.transfer_title.data
        account_to_transfer = form.account_to_transfer.data
        amount = form.amount.data
        password = form.password.data
        user_id = session["user_id"]

        try:
            Transactions.make_transaction(receiver_name=transfer_recipient,
                                          from_account_number=Users.get_user_by_login(user_id).us_act_nb,
                                          to_account_number=account_to_transfer,
                                          amount=amount,
                                          title=transfer_title,
                                          password=password)
        except ValueError as e:
            flash(str(e))
            return flask.render_template("transactions/transfer_money.html", form=form)

        flash("Money transferred successfully")
        return redirect(url_for("get_transactions"))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("transactions/transfer_money.html", form=form)


@app.route("/get_transactions", methods=["GET"])
@login_required
def get_transactions():
    incoming = Transactions.get_transactions_incoming_to_user(session["user_id"])
    outgoing = Transactions.get_transactions_outgoing_from_user(session["user_id"])

    return flask.render_template("transactions/get_transactions.html", incoming=incoming, outgoing=outgoing)


@app.route("/get_all_login_attempts")
@login_required
def get_all_login_attempts():
    login_attempts = LoginAttempts.get_all_login_attempts_for_user(session["user_id"])

    return flask.render_template("login/get_all_login_attempts.html", login_attempts=login_attempts)


@app.route('/send_document', methods=['GET', 'POST'])
@login_required
def send_document():
    form = SendDocumentForm()

    if form.validate_on_submit():
        file = form.file.data
        password = form.password.data

        try:
            Documents.save_encrypted_document(user_id=session['user_id'],
                                              uploaded_file=file,
                                              password=password,
                                              allowed_extensions=app.config['UPLOAD_EXTENSIONS'],
                                              upload_path=app.config['UPLOAD_PATH'])
        except ValueError as e:
            flash(str(e))
            return flask.render_template("documents/send_document.html", form=form,
                                         allowed_extensions=app.config['UPLOAD_EXTENSIONS'])
        except Exception:
            flash("Something went wrong")
            return flask.render_template("documents/send_document.html", form=form,
                                         allowed_extensions=app.config['UPLOAD_EXTENSIONS'])

        return redirect(url_for('get_document'))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("documents/send_document.html", form=form,
                                 allowed_extensions=app.config['UPLOAD_EXTENSIONS'])


@app.route('/get_document', methods=['GET', 'POST'])
@login_required
def get_document():
    user_id = session['user_id']
    user_custom_path = os.path.join(app.config['UPLOAD_PATH'], user_id)

    try:
        filenames = [filename[:-4] for filename in os.listdir(user_custom_path) if filename.endswith(".aes")]
    except FileNotFoundError:
        filenames = []

    return flask.render_template("documents/get_document.html", filenames=filenames)


@app.route('/get_document/<filename>', methods=['GET', 'POST'])
@login_required
def get_document_by_name(filename: str):
    form = AccessDocumentForm()

    if form.validate_on_submit():
        password = form.password.data

        try:
            decrypted_document = Documents.read_encrypted_document(user_id=session['user_id'],
                                                                   filename=filename,
                                                                   password=password,
                                                                   upload_path=app.config['UPLOAD_PATH'])
        except ValueError as e:
            flash(str(e))
            return flask.render_template("access_forms/access_download.html", form=form, filename=filename)

        return flask.send_file(io.BytesIO(decrypted_document), download_name=filename, as_attachment=True)
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("access_forms/access_download.html", form=form, filename=filename)


@app.route('/delete_document/<filename>', methods=['GET', 'POST'])
@login_required
def delete_document_by_name(filename: str):
    form = AccessDocumentForm()

    if form.validate_on_submit():
        password = form.password.data
        user_id = session['user_id']
        try:
            Documents.delete_encrypted_document_from_server(
                user_id=user_id,
                filename=filename,
                password=password,
                upload_path=app.config['UPLOAD_PATH']
            )
        except ValueError as e:
            flash(str(e))
            return flask.render_template("access_forms/access_delete.html", form=form, filename=filename)

        flash("Document deleted successfully")
        return redirect(url_for('get_document'))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("access_forms/access_delete.html", form=form, filename=filename)


@app.route('/access_card_details', methods=['GET', 'POST'])
@login_required
def access_card_details():
    form = AccessDocumentForm()

    if form.validate_on_submit():
        password = form.password.data
        user_id = session['user_id']
        try:
            card_data = CreditCards.get_decrypted_credit_card_for_user(user_id, password)
        except ValueError as e:
            flash(str(e))
            return flask.render_template('access_forms/access_card_details.html', form=form)

        return flask.render_template("access_forms/access_card_details.html", form=form, card_details=card_data)

    return flask.render_template("access_forms/access_card_details.html", form=form)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        time.sleep(app.config['CHANGE_PASSWORD_TIMEOUT'])

        old_password = form.old_password.data
        new_password = form.new_password.data
        repeat_new_password = form.repeat_new_password.data
        user_id = session['user_id']

        if new_password != repeat_new_password:
            flash("Passwords do not match")
            return flask.render_template("passwords/change_password.html", form=form)

        response = check_if_user_provided_correct_password(session, old_password)
        if response:
            flash(response)
            return flask.render_template("passwords/change_password.html", form=form)

        is_password_same = check_if_password_is_same_as_previous(new_password, user_id)
        if is_password_same:
            flash(is_password_same)
            return flask.render_template("passwords/change_password.html", form=form)

        password_strength_errors = check_password_strength(new_password)
        if password_strength_errors:
            [flash(error) for error in password_strength_errors]
            return flask.render_template("passwords/change_password.html", form=form)

        new_salt, hashed_password = hash_new_password_with_new_salt(new_password)

        try:
            Users.update_user_password(user_id, new_password, hashed_password, new_salt.slt_vl, new_salt.slt_id)
        except ValueError as e:
            flash(str(e))
            return flask.render_template("passwords/change_password.html", form=form)

        flash("Password changed successfully")
        return redirect(url_for('index'))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("passwords/change_password.html", form=form)


@app.route('/password_recovery', methods=['GET', 'POST'])
def password_recovery():
    form = PasswordRecoveryCodeForm()

    if form.validate_on_submit():
        time.sleep(app.config['PASSWORD_RECOVERY_TIMEOUT'])
        email = form.email.data
        try:
            user = Users.get_user_by_email(email)
        except ValueError as e:
            flash(str(e))
            return flask.render_template("passwords/password_recovery.html", form=form)

        if user is None:
            flash("User with this email does not exist")
            return flask.render_template("passwords/password_recovery.html", form=form)

        try:
            code = PasswordRecoveryCodes.generate_new_unique_password_recovery_code_for_user(user.us_email)
        except ValueError as e:
            flash(str(e))
            return flask.render_template("passwords/password_recovery.html", form=form)

        flash(f"Recovery code send successfully to email {email}. "
              f"Code is active for {app.config['TIME_ALLOWED_FOR_PASSWORD_RECOVERY']} minute(s). "
              f"Normally you would have to get it from there, but hey, u seam like trustworthy user, so "
              f"just for u here it is: {flask.url_for('password_recovery_verify', password_recovery_code=code)}")

        return redirect(url_for('index'))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("passwords/password_recovery.html", form=form)


@app.route('/password_recovery/verify/<password_recovery_code>', methods=['GET', 'POST'])
def password_recovery_verify(password_recovery_code: str):
    try:
        code_object = verify_provided_password_recovery_code(password_recovery_code)
    except ValueError as e:
        flash(str(e))
        return redirect(url_for('index'))

    form = SetNewPasswordForm()

    if form.validate_on_submit():
        time.sleep(app.config['PASSWORD_RECOVERY_TIMEOUT'])
        user_login = code_object.user_id
        new_password = form.new_password.data
        repeat_new_password = form.repeat_new_password.data

        if new_password != repeat_new_password:
            flash("Passwords do not match")
            return flask.render_template("passwords/set_new_password.html", form=form)

        password_strength_errors = check_password_strength(new_password)
        if password_strength_errors:
            [flash(error) for error in password_strength_errors]
            return flask.render_template("passwords/set_new_password.html", form=form)

        new_salt, hashed_password = hash_new_password_with_new_salt(new_password)
        try:
            Users.update_user_password(user_login, new_password, hashed_password, new_salt.slt_vl,
                                       new_salt.slt_id)
            code_object.delete_password_recovery_code()
        except ValueError as e:
            flash(str(e))
            return flask.render_template("passwords/set_new_password.html", form=form)

        flash("Password changed successfully")
        return redirect(url_for('index'))
    else:
        for error in form.errors:
            flash(form.errors[error][0])

    return flask.render_template("passwords/set_new_password.html", form=form)


@app.errorhandler(404)
def not_found(error):
    app.logger.error(error)
    return flask.render_template('error_pages/404.html'), 404


@app.errorhandler(401)
def unauthorized(error):
    app.logger.error(error)
    return flask.render_template('error_pages/401.html'), 401


@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.error(error)
    return flask.render_template('error_pages/413.html'), 413


@app.errorhandler(500)
def internal_error(error):
    app.logger.error(error)
    return flask.render_template('error_pages/500.html'), 500


app.register_error_handler(404, not_found)
app.register_error_handler(401, unauthorized)
app.register_error_handler(500, internal_error)
