from functools import wraps

from flask import session
from werkzeug.exceptions import HTTPException


class Unauthorized(HTTPException):
    code = 401
    description = 'You are not authorized to access this page.'

def requires_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "authenticated" not in session or not session["authenticated"]:
            raise Unauthorized()
        return func(*args, **kwargs)
    return decorated_function