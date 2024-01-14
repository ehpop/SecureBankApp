"""
This file contains helper functions for views.py, mainly logic shared in multiple views.
"""

import bcrypt
from flask import jsonify

from models import Users, Salts, PasswordRecoveryCodes


def check_if_password_is_same_as_previous(new_password, user_id):
    """
    Checks if new password is the same as the old one.
    :param new_password:
    :param user_id:
    :return:
    """

    new_password_hashed_with_old_salt = bcrypt.hashpw(new_password.encode("utf-8"),
                                                      bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)).hex()
    if new_password_hashed_with_old_salt == Users.get_user_by_login(user_id).us_hsh:
        return jsonify({"error": "New password cannot be the same as old password"}), 400

    return None


def hash_new_password_with_new_salt(new_password: str):
    """
    Hashes new password with new salt.
    :param new_password:
    :return:
    """

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), salt).hex()

    new_salt = Salts(slt_vl=salt.hex())
    new_salt.save_salt()

    return new_salt, hashed_password


def check_if_user_provided_correct_password(session, provided_password):
    user_id = session['user_id']
    is_authenticated = session['authenticated']

    if not is_authenticated or not user_id:
        return jsonify({"error": "Unauthorized request"}), 401

    passw = provided_password.encode("utf-8")
    hashed_password = bytes.fromhex(Users.get_user_by_login(user_id).us_hsh)

    if not bcrypt.checkpw(passw, hashed_password):
        return jsonify({"error": "Wrong credentials"}), 401


def verify_provided_password_recovery_code(password_recovery_code: str):
    try:
        code_object = PasswordRecoveryCodes.get_password_recovery_code_by_code(password_recovery_code)
    except ValueError:
        raise ValueError("Password recovery code not found")

    if not code_object:
        raise ValueError("Password recovery code not found")

    if not PasswordRecoveryCodes.is_code_valid(code_object.code):
        raise ValueError("Password recovery code is not valid")

    return code_object
