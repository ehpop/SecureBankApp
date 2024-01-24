"""
This file contains helper functions for views.py, mainly logic shared in multiple views.
"""

import bcrypt
from flask import current_app

from models import Users, Salts, PasswordRecoveryCodes


def check_if_password_is_same_as_previous(new_password, user_id):
    """
    Checks if new password is the same as the old one.
    :param new_password:
    :param user_id:
    :return: None if new password is not the same as the old one, error message otherwise.
    """

    new_password_hashed_with_old_salt = bcrypt.hashpw(new_password.encode("utf-8"),
                                                      bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)).hex()
    if new_password_hashed_with_old_salt == Users.get_user_by_login(user_id).us_hsh:
        return "New password cannot be the same as the old one"

    return None


def hash_new_password_with_new_salt(new_password: str):
    """
    Hashes new password with new salt.
    :param new_password: new password
    :return: new salt and hashed password
    """

    salt = bcrypt.gensalt(current_app.config["BCRYPT_LOG_WORK_FACTOR"])
    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    return new_salt, hashed_password


def check_if_user_provided_correct_password(session, provided_password):
    """
    Checks if user provided correct password.
    :param session: current session
    :param provided_password: password provided by user
    :return: Error message if password is incorrect, None otherwise.
    """
    user_id = session['user_id']
    is_authenticated = session['authenticated']

    if not is_authenticated or not user_id:
        return "User not authenticated"

    passw = provided_password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return "Wrong credentials"


def verify_provided_password_recovery_code(password_recovery_code: str):
    """
    Verifies if provided password recovery code is valid.
    :param password_recovery_code: value of password recovery code
    :return: code object if code is valid
    :raises: ValueError if code is not valid
    """
    try:
        code_object = PasswordRecoveryCodes.get_password_recovery_code_by_code(password_recovery_code)
    except ValueError:
        raise ValueError("Password recovery code not found")

    if not code_object:
        raise ValueError("Password recovery code not found")

    if not PasswordRecoveryCodes.is_code_valid(code_object.code):
        raise ValueError("Password recovery code is expired")

    return code_object
