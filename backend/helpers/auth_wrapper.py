from functools import wraps
from flask import jsonify, session, redirect, url_for

def requires_authentication(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or "authenticated" not in session or not session["authenticated"]:
            return redirect(url_for('test', _method="GET"))
        return func(*args, **kwargs)
    return decorated_function