"""
Password must contain at least 1 uppercase letter, 1 number and 1 special character.
"""
password_regex = "^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-=_+]).{8,16}$"

"""
Username can contain only letters, numbers and underscores.
"""
username_regex = "^[a-zA-Z0-9_]{2,20}$"

"""
Account must be polish IBAN number.
"""
iban_regex = "^PL[0-9]{26}$"
