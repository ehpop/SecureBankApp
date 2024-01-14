import math
import secrets
from datetime import datetime, timedelta

import bcrypt
from flask_sqlalchemy import SQLAlchemy

from helpers.generate_numbers import generate_account_number, generate_random_consecutive_numbers

db = SQLAlchemy()


class Users(db.Model):
    us_lgn = db.Column(db.String, primary_key=True)
    us_email = db.Column(db.String, unique=True, nullable=False)
    us_nme = db.Column(db.String, nullable=False)
    us_hsh = db.Column(db.String, nullable=False)
    us_act_nb = db.Column(db.String, unique=True, nullable=False)
    us_blnc = db.Column(db.Integer, nullable=False)
    salt_id = db.Column(db.Integer, db.ForeignKey("salts.slt_id"))
    us_crd_nb_id = db.Column(db.Integer, db.ForeignKey("credit_cards.crd_id"))

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
    def update_user_password(user_id, new_password, hashed_password, new_salt_id):
        user = Users.get_user_by_login(user_id)

        try:
            UserCredentials.delete_all_combinations_for_user(user_id)
            UserCredentials.generate_new_password_combinations(new_password, user_id)
        except ValueError:
            raise ValueError(f"Error occurred while updating password for user {user_id}")

        user.us_hsh = hashed_password
        user.salt_id = new_salt_id
        db.session.commit()

    @staticmethod
    def generate_new_card_number():
        raise NotImplementedError

    def save_user(self):
        db.session.add(self)
        db.session.commit()

    def remove_user(self):
        db.session.delete(self)
        db.session.commit()


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

    # TODO: make this depend on app context config
    @staticmethod
    def generate_new_password_combinations(plain_password: str, username: str, amount_of_combinations=10,
                                           amount_of_chars_in_combination=6):
        if Users.get_user_by_login(username) is None:
            raise ValueError(f"User with login {username} does not exist")

        generated_combinations = []
        max_amount_of_combinations = min(math.factorial(len(plain_password)), amount_of_combinations)
        for _ in range(max_amount_of_combinations):
            combination_of_password_letters = generate_random_consecutive_numbers(len(plain_password),
                                                                                  amount_of_chars_in_combination)

            while combination_of_password_letters in generated_combinations:
                combination_of_password_letters = generate_random_consecutive_numbers(len(plain_password),
                                                                                      amount_of_chars_in_combination)

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

        UserCredentials.query.where(UserCredentials.usr_id == user_id).delete()
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

    def remove_salt(self):
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

    @staticmethod
    def get_credit_card_by_id(card_id: int):
        return CreditCards.query.where(CreditCards.crd_id == card_id).first()

    @staticmethod
    def get_credit_card_by_owner(card_owner: str):
        return CreditCards.query.where(CreditCards.owner_id == card_owner).first()

    @staticmethod
    def get_credit_card_by_number(card_number: str):
        return CreditCards.query.where(CreditCards.crd_nb == card_number).first()
