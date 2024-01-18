from flask import current_app
from password_strength import PasswordPolicy
from password_strength.tests import ATest

MIN_UPPERCASE_LETTERS = 1
MIN_NUMBERS = 1
MIN_SPECIAL_CHARACTERS = 1
MIN_ENTROPY_BITS = 32

policy = PasswordPolicy.from_names(
    length=current_app.config["MIN_PASSWORD_LENGTH"],
    uppercase=MIN_UPPERCASE_LETTERS,
    numbers=MIN_NUMBERS,
    special=MIN_SPECIAL_CHARACTERS,
    entropybits=MIN_ENTROPY_BITS
)


def map_errors_to_messages(errors: list) -> list:
    """
    Maps errors from password_strength to human-readable messages
    :param errors: Errors to map
    :return: List of messages
    """
    messages = []
    current_app.logger.info([error.name() for error in errors])
    for error in errors:
        error_name = error.name().upper()
        if error_name == "LENGTH":
            messages.append("Password must be at least 8 characters long.")
        elif error_name == "UPPERCASE":
            messages.append("Password must contain at least 1 uppercase letter.")
        elif error_name == "NUMBERS":
            messages.append("Password must contain at least 1 number.")
        elif error_name == "SPECIAL":
            messages.append("Password must contain at least 1 special character.")
        elif error_name == "NONLETTERS":
            messages.append("Password must contain at least 2 non-letter characters.")
        elif error_name == "ENTROPYBITS":
            messages.append(
                "Password must contain at least 32 bits of entropy. (Make it a bit longer, or more random ;])")
        elif error_name == "MAXLENGTHTEST":
            messages.append("Password must be at most 16 characters long.")

    return messages


def check_password_strength(password: str) -> list:
    """
    Checks password strength against the following criteria:
    - Min length: 8 characters
    - Max length: 16 characters
    - Uppercase letters: 1
    - Numbers: 1
    - Special characters: 1
    - Entropy bits: 32
    :param password: The password to check
    :return: Empty list if password is strong, list of error messages otherwise
    """
    results = policy.test(password)

    max_length_policy = PasswordPolicy(MaxLengthTest(current_app.config['MAX_PASSWORD_LENGTH']))
    max_length_policy_result = max_length_policy.test(password)

    if len(max_length_policy_result) > 0:
        results.append(max_length_policy_result[0])

    if len(results) > 0:
        return map_errors_to_messages(results)

    return []


class MaxLengthTest(ATest):
    """
    Test for maximum password length
    """

    def __init__(self, max_length):
        super(MaxLengthTest, self).__init__(max_length)
        self.max_length = max_length

    def test(self, ps):
        return ps.length <= self.max_length

    def __str__(self):
        return 'Password is too long (max length: %d)' % self.max_length

    def __repr__(self):
        return '(%s: %s)' % (self.__class__.__name__, self.max_length)
