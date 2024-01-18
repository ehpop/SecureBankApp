import math
import os
import secrets
from datetime import datetime, timedelta

import bcrypt
from flask import current_app
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from helpers.file_content_checker import check_file_content_based_on_extension, get_file_extension
from helpers.file_encrypter import encrypt_bytes_with_password_and_salt, decrypt_bytes_with_password_and_salt
from helpers.generate_numbers import generate_account_number, generate_random_consecutive_numbers, \
    generate_random_password_recovery_code
from helpers.generate_numbers import generate_card_data
from helpers.password_checker import check_password_strength

db = SQLAlchemy()


class Users(db.Model, UserMixin):
    us_lgn = db.Column(db.String, primary_key=True)
    us_email = db.Column(db.String, unique=True, nullable=False)
    us_nme = db.Column(db.String, nullable=False)
    us_hsh = db.Column(db.String, nullable=False)
    us_act_nb = db.Column(db.String, unique=True, nullable=False)
    us_blnc = db.Column(db.Integer, nullable=False)
    salt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))
    us_crd_nb_id = db.Column(db.Integer, db.ForeignKey("credit_cards.crd_id"))

    def get_id(self):
        return self.us_lgn

    def __repr__(self):
        return f"<User {self.us_lgn}>"

    def __str__(self):
        return f"login: {self.us_lgn}, email: {self.us_email}, name: {self.us_nme}, account number: {self.us_act_nb}, balance: {self.us_blnc}"

    def to_dict(self):
        return {
            "login": self.us_lgn,
            "email": self.us_email,
            "name": self.us_nme,
            "account_number": self.us_act_nb,
            "balance": self.us_blnc
        }

    def to_json(self):
        return f"""{{
            "login": "{self.us_lgn}",
            "email": "{self.us_email}",
            "name": "{self.us_nme}",
            "account_number": "{self.us_act_nb}",
            "balance": "{self.us_blnc}"
        }}"""

    def save_user(self):
        db.session.add(self)
        db.session.commit()

    def delete_user(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_user_by_login(login: str):
        return Users.query.where(Users.us_lgn == login).first()

    @staticmethod
    def get_user_by_email(email: str):
        return Users.query.where(Users.us_email == email).first()

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
    def is_email_taken(email: str):
        return Users.query.where(Users.us_email == email).count() > 0

    @staticmethod
    def is_account_number_taken(account_number: str):
        return Users.query.where(Users.us_act_nb == account_number).count() > 0

    @staticmethod
    def is_card_number_taken(card_number: str):
        raise NotImplementedError

    @staticmethod
    def generate_new_account_number():
        acct_number = generate_account_number()
        is_acct_number_taken = Users.is_account_number_taken(acct_number)

        while is_acct_number_taken:
            acct_number = generate_account_number()
            is_acct_number_taken = Users.is_account_number_taken(acct_number)

        return acct_number

    @staticmethod
    def update_user_password(user_id, new_password, hashed_password, new_salt_value, new_salt_id):
        """
        Updates user password. It generates new password combinations for the user, deletes the old ones,
        and updates the user's password and salt id in the database.

        **IMPORTANT**: This method deletes old credit card for user and generates a new one, because
        card data was encrypted with the old password.

        :param user_id:
        :param new_password:
        :param hashed_password:
        :param new_salt_value:
        :param new_salt_id:
        :return:
        """
        user = Users.get_user_by_login(user_id)

        try:
            UserCredentials.delete_all_combinations_for_user(user_id)
            UserCredentials.generate_new_password_combinations(new_password, user_id)
        except ValueError:
            raise ValueError(f"Error occurred while updating password for user {user_id}")

        old_salt_id = user.salt_id
        old_credit_card_id = user.us_crd_nb_id

        user.us_hsh = hashed_password
        user.salt_id = new_salt_id
        user.us_crd_nb_id = CreditCards.generate_new_encrypted_credit_card_with_password_and_salt(new_password,
                                                                                                  new_salt_value,
                                                                                                  new_salt_id).crd_id

        CreditCards.get_credit_card_by_id(old_credit_card_id).delete_credit_card()
        try:
            Salts.get_salt_by_id(old_salt_id).delete_salt()
        except Exception:
            raise ValueError(f"Error occurred while deleting salt with id {old_salt_id}")

        db.session.commit()

    @staticmethod
    def generate_new_card_number():
        raise NotImplementedError

    @staticmethod
    def login_user(username: str, password: str, ip_address: str, combination_id: str):
        user = Users.get_user_by_login(username)
        max_failed_login_attempts = current_app.config['MAX_FAILED_LOGIN_ATTEMPTS']
        if user is None:
            raise ValueError("Wrong credentials")

        login_attempt = LoginAttempts(username=username, ip_address=ip_address, success=False)

        if LoginAttempts.calculate_failed_login_attempts_in_period(username,
                                                                   ip_address) >= max_failed_login_attempts:
            login_attempt.save_login_attempt()
            raise ValueError(
                f"Too many failed login attempts. Try again in {current_app.config['FAILED_LOGIN_ATTEMPTS_LOCKOUT_TIME']} minutes.")

        if not UserCredentials.check_password_combination_for_id(combination_id, password):
            login_attempt.save_login_attempt()
            raise ValueError("Wrong credentials")

        login_attempt.success = True
        login_attempt.save_login_attempt()

        return user

    @staticmethod
    def register_user(username: str, email: str, password: str, name: str, lastname: str, repeat_password: str):
        if password != repeat_password:
            raise ValueError("Passwords do not match")

        password_strength_errors = check_password_strength(password)
        if password_strength_errors:
            raise Users.PasswordErrorsException(password_strength_errors)

        if Users.is_login_taken(username):
            raise ValueError("Login already taken")

        if Users.is_email_taken(email):
            raise ValueError("Email already taken")

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()

        new_salt = Salts(slt_vl=salt.hex())
        new_salt.save_salt()

        credit_card = CreditCards.generate_new_encrypted_credit_card_with_password_and_salt(password,
                                                                                            new_salt.slt_vl,
                                                                                            new_salt.slt_id)

        new_user = Users()
        new_user.us_lgn = username
        new_user.us_email = email
        new_user.us_nme = f"{name} {lastname}"
        new_user.us_hsh = hashed_password
        new_user.us_act_nb = Users.generate_new_account_number()
        new_user.us_blnc = current_app.config['DEFAULT_USER_BALANCE']
        new_user.salt_id = new_salt.slt_id
        new_user.us_crd_nb_id = credit_card.crd_id

        new_user.save_user()

        UserCredentials.generate_new_password_combinations(password,
                                                           new_user.us_lgn)

        return new_user

    class PasswordErrorsException(Exception):
        def __init__(self, error_list):
            self.error_list = error_list
            super().__init__(f"Password errors: {error_list}")


class UserCredentials(db.Model):
    AMOUNT_OF_ACTIVE_TIME = 10

    cmb_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    usr_id = db.Column(db.String, nullable=False)
    pswd_ltrs_nmbrs = db.Column(db.String, nullable=False)
    hsh_val = db.Column(db.String, nullable=False)
    lst_activated_date = db.Column(db.DateTime, default=None, nullable=True)
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
    def check_password_combination_for_id(combination_id: str, password: str) -> bool:
        """
        Checks if the password combination is correct for a given id. It also must be active, meaning
        user must have asked server for this specific combination in the last
        UserCredentials.AMOUNT_OF_ACTIVE_TIME minutes.

        **IMPORTANT**: This method automatically removes last activated date from the password combination
        so that it won't be used again immediately.

        :param combination_id: ID of the password combination to check
        :param password: Password to check
        :return: True if the password combination is correct, and it was active at the time, False otherwise
        """
        combination = UserCredentials.get_user_credentials_by_id(combination_id)

        if combination is None:
            return False

        is_combination_active = UserCredentials.is_password_combination_active(combination_id)

        if not is_combination_active:
            return False

        is_password_correct = bcrypt.checkpw(password.encode("utf-8"), bytes.fromhex(combination.hsh_val))

        if not is_password_correct:
            return False

        combination.lst_activated_date = None
        db.session.commit()
        return True

    @staticmethod
    def get_random_credentials_for_user(user_id: str):
        """
        Gets random credentials for a given user. If there are no active credentials, it activates a random one,
        by setting the lst_activated_date to the current date. If there are no credentials for a given user, it
        returns None.

        :param user_id: Login of the user for whom the credentials should be returned
        :return: credentials object
        """

        all_user_credentials = UserCredentials.query.where(UserCredentials.usr_id == user_id).all()
        if all_user_credentials is None:
            return None

        active_credentials = [credential for credential in all_user_credentials if
                              UserCredentials.is_password_combination_active(credential.cmb_id)]

        if len(active_credentials) > 0:
            return active_credentials[0]

        try:
            random_credentials = secrets.choice(all_user_credentials)
            random_credentials.lst_activated_date = datetime.utcnow()
            db.session.commit()
        except IndexError:
            return None

        return random_credentials

    @staticmethod
    def get_fake_credentials():
        user_id = "fake_user"
        combinations = set()
        max_password_length = current_app.config['MAX_PASSWORD_LENGTH']
        while len(combinations) < current_app.config['AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD']:
            combinations.add(1 + secrets.randbelow(max_password_length + 1))

        return user_id, list(sorted(combinations))

    @staticmethod
    def is_password_combination_active(combination_id: str) -> bool:
        """
        Checks if the password combination is active. Meaning that it was activated less than
        UserCredentials.AMOUNT_OF_ACTIVE_TIME minutes ago.
        :param combination_id: id of the password combination to check
        :return: True if the password combination is active, False otherwise
        """

        combination = UserCredentials.get_user_credentials_by_id(combination_id)

        if combination is None:
            return False

        return combination.lst_activated_date is not None \
            and combination.lst_activated_date > datetime.utcnow() - timedelta(
                minutes=UserCredentials.AMOUNT_OF_ACTIVE_TIME)

    @staticmethod
    def parse_list_of_numbers_from_string(string: str) -> list[int]:
        return [int(number) for number in string.lstrip("{").rstrip("}").split(",")]

    @staticmethod
    def generate_new_password_combinations(plain_password: str, username: str):
        if Users.get_user_by_login(username) is None:
            raise ValueError(f"User with login {username} does not exist")

        generated_combinations = []
        max_amount_of_combinations = min(math.factorial(len(plain_password)),
                                         current_app.config['AMOUNT_OF_COMBINATIONS_GENERATED_FOR_PASSWORD'])
        for _ in range(max_amount_of_combinations):
            combination_of_password_letters = generate_random_consecutive_numbers(len(plain_password),
                                                                                  current_app.config[
                                                                                      'AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD'])

            while combination_of_password_letters in generated_combinations:
                combination_of_password_letters = generate_random_consecutive_numbers(len(plain_password),
                                                                                      current_app.config[
                                                                                          'AMOUNT_OF_CHARS_REQUIRED_IN_PASSWORD'])

            letters_in_password = "".join([plain_password[i - 1] for i in combination_of_password_letters])
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(letters_in_password.encode("utf-8"), salt).hex()

            new_salt = Salts(slt_vl=salt.hex())
            new_salt.save_salt()

            user_credentials = UserCredentials(usr_id=username,
                                               pswd_ltrs_nmbrs=combination_of_password_letters,
                                               hsh_val=hashed_password,
                                               slt_id=new_salt.slt_id)
            user_credentials.save_user_credentials()

    @staticmethod
    def delete_all_combinations_for_user(user_id: str):
        if Users.get_user_by_login(user_id) is None:
            raise ValueError(f"User with login {user_id} does not exist")

        all_credentials = UserCredentials.query.where(UserCredentials.usr_id == user_id)
        all_credentials_salt_ids = [credential.slt_id for credential in all_credentials]
        all_credentials.delete()
        db.session.commit()

        for salt_id in all_credentials_salt_ids:
            try:
                Salts.get_salt_by_id(salt_id).delete_salt()
            except Exception:
                raise ValueError(f"Error occurred while deleting salt with id {salt_id}")
        db.session.commit()


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

    def delete_salt(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_salt_by_id(salt_id: int):
        return Salts.query.where(Salts.slt_id == salt_id).first()


class Transactions(db.Model):
    trns_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
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
        return Transactions.query.all()

    @staticmethod
    def get_transactions_by_account_number(account_number: str):
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

        if user is None:
            return []

        return Transactions.query.where(Transactions.act_frm == user.us_act_nb).all()

    @staticmethod
    def make_transaction(from_account_number: str, to_account_number: str, amount: int, password: str,
                         title="Transfer title",
                         transfer_date=datetime.utcnow()):
        """
        Makes a transaction from one account to another.
        :param from_account_number: Account number from which the transaction should be made
        :param to_account_number: Account number to which the transaction should be made
        :param amount: Amount of money to transfer
        :param password: Password of the user that is making the transaction
        :param title: Title of the transaction
        :param transfer_date: Date of the transaction
        :raises ValueError: If the account from which the transaction should be made does not exist
        :raises ValueError: If the account to which the transaction should be made does not exist
        :raises ValueError: If there is not enough money on the account from which the transaction should be made
        """

        issuer = Users.get_user_by_account(from_account_number)
        receiver = Users.get_user_by_account(to_account_number)

        if not Users.check_password_for_user(issuer.us_lgn, password):
            raise ValueError("Wrong credentials")

        if issuer is None:
            raise ValueError("Account from which you want to make transaction does not exist")

        if receiver is None:
            raise ValueError("Account to which you want to make transaction does not exist")

        if issuer.us_blnc < amount:
            raise ValueError("Not enough money on the account")

        issuer.us_blnc -= amount
        receiver.us_blnc += amount

        transaction = Transactions(act_frm=from_account_number, act_to=to_account_number, trns_amt=amount,
                                   trns_ttl=title, trns_dt=transfer_date)
        transaction.save_transaction()

        issuer.save_user()
        receiver.save_user()


class Documents(db.Model):
    dcm_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dcm_ad_dt = db.Column(db.String, nullable=False)
    dcm_ttl = db.Column(db.String, nullable=False)
    dcm_typ = db.Column(db.String, nullable=False)
    dcm_hsh = db.Column(db.String, nullable=False)
    dcm_slt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))
    own_id = db.Column(db.String, db.ForeignKey("users.us_lgn"))

    def __repr__(self):
        return f"<Document {self.dcm_id}>"

    def __str__(self):
        return f"date: {self.dcm_ad_dt}, title: {self.dcm_ttl}, type: {self.dcm_typ}, owner: {self.own_id}"

    def to_dict(self):
        return {
            "date": self.dcm_ad_dt,
            "title": self.dcm_ttl,
            "type": self.dcm_typ,
            "owner": self.own_id
        }

    def to_json(self):
        return f"""{{
            "date": "{self.dcm_ad_dt}",
            "title": "{self.dcm_ttl}",
            "type": "{self.dcm_typ}",
            "owner": "{self.own_id}"
        }}"""

    def save_document(self):
        db.session.add(self)
        db.session.commit()

    def delete_document(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_document_by_id(document_id: int):
        return Documents.query.where(Documents.dcm_id == document_id).first()

    @staticmethod
    def get_all_documents():
        return Documents.query.all()

    @staticmethod
    def get_all_documents_for_user(user_login: str):
        return Documents.query.where(Documents.own_id == user_login).all()

    @staticmethod
    def get_all_documents_for_user_by_type(user_login: str, document_type: str):
        return Documents.query.where(Documents.own_id == user_login).where(Documents.dcm_typ == document_type).all()

    @staticmethod
    def get_document_for_user_by_filename(user_login: str, filename: str):
        return Documents.query.where(Documents.own_id == user_login).where(Documents.dcm_ttl == filename).first()

    @staticmethod
    def save_encrypted_document(user_id: str, password: str, uploaded_file, allowed_extensions: list[str],
                                upload_path: str):
        if uploaded_file.filename == '':
            raise ValueError("No selected file")

        uploaded_file_content = uploaded_file.stream.read()
        uploaded_file_name = secure_filename(uploaded_file.filename)

        if not uploaded_file_name:
            raise ValueError("Invalid file name. Please change it before uploading again.")

        if not password or not user_id:
            raise ValueError("Unauthorized request")

        errors = check_password_strength(password)
        if errors:
            raise ValueError(errors)

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()
        new_salt = Salts(slt_vl=salt.hex())
        new_salt.save_salt()

        file_extension = get_file_extension(uploaded_file_name)

        if not file_extension in allowed_extensions:
            raise ValueError("Invalid file extension")

        if not check_file_content_based_on_extension(uploaded_file.stream, file_extension):
            raise ValueError("Invalid file content")

        try:
            user_custom_path = os.path.join(upload_path, user_id)
            if not os.path.exists(user_custom_path):
                os.makedirs(user_custom_path)

            salt = bytes.fromhex(Salts.get_salt_by_id(Users.get_user_by_login(user_id).salt_id).slt_vl)
            file_encrypted = encrypt_bytes_with_password_and_salt(uploaded_file_content, password, salt)

            with open(os.path.join(user_custom_path, uploaded_file_name + '.aes'), "wb") as f:
                f.write(file_encrypted)

        except Exception as e:
            current_app.logger.info(e)
            raise ValueError(f"Error occurred while encrypting file.")

        document = Documents(own_id=user_id,
                             dcm_ttl=uploaded_file_name,
                             dcm_typ=file_extension,
                             dcm_hsh=hashed_password,
                             dcm_slt_id=new_salt.slt_id,
                             dcm_ad_dt=datetime.utcnow())

        document.save_document()

        return document

    @staticmethod
    def __verify_access_to_file__(document, password):
        if not document:
            raise ValueError("File not found")

        passw = password.encode("utf-8")
        hashed_password = bytes.fromhex(document.dcm_hsh)

        if not bcrypt.checkpw(passw, hashed_password):
            raise ValueError("Wrong credentials")

    @staticmethod
    def read_encrypted_document(user_id: str, filename: str, password: str, upload_path: str):
        document = Documents.get_document_for_user_by_filename(user_id, filename)

        try:
            Documents.__verify_access_to_file__(document, password)
        except ValueError:
            raise ValueError("Wrong credentials")

        filename = document.dcm_ttl
        user_custom_path = os.path.join(upload_path, user_id)

        try:
            with open(os.path.join(user_custom_path, filename + '.aes'), "rb") as f:
                content = f.read()
        except FileNotFoundError:
            raise ValueError("File not found")

        if not content:
            raise ValueError("File is empty")

        salt = bytes.fromhex(Salts.get_salt_by_id(Users.get_user_by_login(user_id).salt_id).slt_vl)
        decrypted_data = decrypt_bytes_with_password_and_salt(content, password, salt)

        return decrypted_data

    @staticmethod
    def delete_encrypted_document_from_server(user_id: str, filename: str, password: str, upload_path: str):
        document = Documents.get_document_for_user_by_filename(user_id, filename)

        try:
            Documents.__verify_access_to_file__(document, password)
        except ValueError as access_error:
            raise access_error

        filename = document.dcm_ttl
        user_custom_path = os.path.join(upload_path, user_id)

        try:
            os.remove(os.path.join(user_custom_path, filename + '.aes'))
        except FileNotFoundError:
            raise ValueError("File not found")

        documents_salt_id = document.dcm_slt_id

        document.delete_document()
        Salts.get_salt_by_id(documents_salt_id).delete_salt()


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
    def calculate_failed_login_attempts_in_period(username: str, ip_address: str) -> int:
        """
        Calculates the amount of failed login attempts in a given period of time.
        :param username: username of the user that is trying to log in
        :param ip_address: ip address of the user that is trying to log in
        :return: amount of failed login attempts in a given period of time
        """
        period_of_time = current_app.config['FAILED_LOGIN_ATTEMPTS_LOCKOUT_TIME']
        all_login_attempts_for_user_and_ip = (LoginAttempts.query
                                              .where(LoginAttempts.username == username)
                                              .where(LoginAttempts.ip_address == ip_address)
                                              .where(
            LoginAttempts.timestamp > datetime.utcnow() - timedelta(minutes=period_of_time))
                                              .order_by(LoginAttempts.timestamp.desc()))

        last_successful_login_attempt = [attempt for attempt in all_login_attempts_for_user_and_ip if attempt.success]
        if len(last_successful_login_attempt) > 0:
            failed_login_attempts_since_last_successful_login = [attempt for attempt in
                                                                 all_login_attempts_for_user_and_ip if
                                                                 not attempt.success and attempt.timestamp >
                                                                 last_successful_login_attempt[0].timestamp]

            return len(failed_login_attempts_since_last_successful_login)
        else:
            return all_login_attempts_for_user_and_ip.count()

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
        datetime.utcnow().time()
        return [{"ip_address": login_attempt.ip_address,
                 "date": login_attempt.timestamp.date(),
                 "time": login_attempt.timestamp.strftime('%H:%M:%S'),
                 "success": login_attempt.success} for login_attempt in
                LoginAttempts.query.where(LoginAttempts.username == username).order_by(
                    LoginAttempts.timestamp.desc()).all()]

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


class CreditCards(db.Model):
    crd_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    crd_nb_hidden = db.Column(db.String, nullable=False)
    crd_cvc_hidden = db.Column(db.String, nullable=False)
    crd_exp_dt_hidden = db.Column(db.String, nullable=False)
    crd_nb = db.Column(db.String, nullable=False)
    crd_cvc = db.Column(db.String, nullable=False)
    crd_exp_dt = db.Column(db.String, nullable=False)
    slt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))

    def __repr__(self):
        return f"<CreditCard {self.crd_id}>"

    def __str__(self):
        return f"card number: {self.crd_nb_hidden}, card cvc: {self.crd_cvc_hidden}, card expiration date: {self.crd_exp_dt_hidden}, card credit limit: {self.crd_crdt_lmt}, card balance: {self.crd_blnc}"

    def to_dict(self):
        return {
            "card_number": self.crd_nb,
            "card_cvc": self.crd_cvc,
            "card_expiration_date": self.crd_exp_dt,
            "card_credit_limit": self.crd_crdt_lmt,
            "card_balance": self.crd_blnc
        }

    def to_json(self):
        return f"""{{
            "card_number": "{self.crd_nb_hidden}",
            "card_cvc": "{self.crd_cvc}",
            "card_expiration_date": "{self.crd_exp_dt}",
            "card_credit_limit": "{self.crd_crdt_lmt}",
            "card_balance": "{self.crd_blnc}"
        }}"""

    def save_credit_card(self):
        db.session.add(self)
        db.session.commit()

    def delete_credit_card(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_credit_card_by_id(card_id: int):
        return CreditCards.query.where(CreditCards.crd_id == card_id).first()

    @staticmethod
    def get_credit_card_by_owner(card_owner: str):
        card_id = Users.get_user_by_login(card_owner).us_crd_nb_id
        return CreditCards.query.where(CreditCards.crd_id == card_id).first()

    @staticmethod
    def get_credit_card_by_number(card_number: str):
        return CreditCards.query.where(CreditCards.crd_nb == card_number).first()

    @staticmethod
    def generate_new_encrypted_credit_card_with_password_and_salt(password, salt_val, salt_id):
        new_card_details, hidden_card_details = generate_card_data()

        card_number_bytes = new_card_details['number'].encode("utf-8")
        cvc_bytes = new_card_details['cvc'].encode("utf-8")
        expiry_date_bytes = new_card_details['expiry_date'].encode("utf-8")

        credit_card = CreditCards(crd_nb_hidden=hidden_card_details['number'],
                                  crd_cvc_hidden=hidden_card_details['cvc'],
                                  crd_exp_dt_hidden=hidden_card_details['expiry_date'],
                                  crd_nb=encrypt_bytes_with_password_and_salt(card_number_bytes
                                                                              , password, salt_val).hex(),
                                  crd_cvc=encrypt_bytes_with_password_and_salt(cvc_bytes,
                                                                               password, salt_val).hex(),
                                  crd_exp_dt=encrypt_bytes_with_password_and_salt(expiry_date_bytes
                                                                                  , password,
                                                                                  salt_val).hex(),
                                  slt_id=salt_id)

        credit_card.save_credit_card()

        return credit_card

    @staticmethod
    def get_decrypted_credit_card_for_user(user_id: str, password: str):
        credit_card = CreditCards.get_credit_card_by_owner(user_id)

        if credit_card is None:
            raise ValueError(f"Card for user {user_id} does not exist")

        salt = Salts.get_salt_by_id(credit_card.slt_id)

        card_number = decrypt_bytes_with_password_and_salt(bytes.fromhex(credit_card.crd_nb), password, salt.slt_vl)
        cvc = decrypt_bytes_with_password_and_salt(bytes.fromhex(credit_card.crd_cvc), password, salt.slt_vl)
        expiry_date = decrypt_bytes_with_password_and_salt(bytes.fromhex(credit_card.crd_exp_dt), password, salt.slt_vl)

        return {
            "number": card_number.decode("utf-8"),
            "cvc": cvc.decode("utf-8"),
            "expiry_date": expiry_date.decode("utf-8")
        }


class PasswordRecoveryCodes(db.Model):
    TIME_ALLOWED_FOR_PASSWORD_RECOVERY = 5

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String, db.ForeignKey("users.us_lgn"))
    code = db.Column(db.String(64), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<PasswordRecoveryCode {self.id}>"

    def __str__(self):
        return f"user_id: {self.user_id}, code: {self.code}, timestamp: {self.timestamp}"

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "code": self.code,
            "timestamp": self.timestamp
        }

    def to_json(self):
        return f"""{{
            "user_id": "{self.user_id}",
            "code": "{self.code}",
            "timestamp": "{self.timestamp}"
        }}"""

    def save_password_recovery_code(self):
        db.session.add(self)
        db.session.commit()

    def delete_password_recovery_code(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def get_password_recovery_code_by_id(code_id: int):
        return PasswordRecoveryCodes.query.where(PasswordRecoveryCodes.id == code_id).first()

    @staticmethod
    def get_password_recovery_code_by_code(code: str):
        return PasswordRecoveryCodes.query.where(PasswordRecoveryCodes.code == code).first()

    @staticmethod
    def get_password_recovery_code_by_user_id(user_id: str):
        return PasswordRecoveryCodes.query.where(PasswordRecoveryCodes.user_id == user_id).first()

    @staticmethod
    def get_password_recovery_code_by_user_email(user_email: str):
        user = Users.get_user_by_email(user_email)
        if user is None:
            return None

        return PasswordRecoveryCodes.get_password_recovery_code_by_user_id(user.us_lgn)

    @staticmethod
    def is_code_taken(code: str):
        return PasswordRecoveryCodes.query.where(PasswordRecoveryCodes.code == code).count() > 0

    @staticmethod
    def generate_new_unique_password_recovery_code_for_user(user_email: str):
        """
        Generates a new unique password recovery code for a user. If the user already has a password recovery code,
        it checks if it is still valid. If it is, it returns the old code. If it is not, it generates a new one, and
        deletes the old one.
        :return: password recovery code
        :raises ValueError: If the user does not exist
        """
        user = Users.get_user_by_email(user_email)
        if user is None:
            raise ValueError(f"User with email {user_email} does not exist")

        code_for_user = PasswordRecoveryCodes.get_password_recovery_code_by_user_id(user.us_lgn)
        if code_for_user is not None:
            if code_for_user.timestamp > datetime.utcnow() - timedelta(
                    minutes=PasswordRecoveryCodes.TIME_ALLOWED_FOR_PASSWORD_RECOVERY):
                return code_for_user.code
            else:
                code_for_user.delete_password_recovery_code()

        code = generate_random_password_recovery_code()
        is_code_taken = PasswordRecoveryCodes.is_code_taken(code)

        while is_code_taken:
            code = generate_random_password_recovery_code()
            is_code_taken = PasswordRecoveryCodes.is_code_taken(code)

        password_recovery_code = PasswordRecoveryCodes(user_id=user.us_lgn, code=code, timestamp=datetime.utcnow())
        password_recovery_code.save_password_recovery_code()

        return password_recovery_code.code

    @staticmethod
    def is_code_valid(code: str) -> bool:
        """
        Checks if the password recovery code is valid. Meaning that it was generated less than
        PasswordRecoveryCodes.TIME_ALLOWED_FOR_PASSWORD_RECOVERY minutes ago.
        :param code: password recovery code to check
        :return: True if the password recovery code is valid, False otherwise
        """
        password_recovery_code = PasswordRecoveryCodes.query.where(PasswordRecoveryCodes.code == code).first()

        if password_recovery_code is None:
            return False

        return password_recovery_code.timestamp > datetime.utcnow() - timedelta(
            minutes=PasswordRecoveryCodes.TIME_ALLOWED_FOR_PASSWORD_RECOVERY)

    @staticmethod
    def send_password_recovery_code(user_email, code):
        """
        Sends password recovery code to the user.
        :param user_email: email of the user
        :param code: password recovery code
        :raises ValueError: If the user does not exist
        """
        user = Users.get_user_by_email(user_email)
        if user is None:
            raise ValueError(f"User with email {user_email} does not exist")

        current_app.logger.info(f"Sending password recovery code {code} to email: {user_email}")
