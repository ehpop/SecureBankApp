from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

import bcrypt, secrets

db = SQLAlchemy()


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
