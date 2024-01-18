import datetime
import random
import secrets


def generate_account_number() -> str:
    """
    Generates a random Polish IBAN number.
    PL IBAN format: PLXX XXXX XXXX XXXX XXXX XXXX XXXX
    'PL' (2 characters) + 26 digits

    :returns: generated account number unique to the database
    """
    iban_prefix = 'PL'
    iban_numbers_length = 26
    pl_iban = iban_prefix + ''.join(str(random.randint(0, 9)) for _ in range(iban_numbers_length))

    return pl_iban


def generate_card_data() -> (dict, dict):
    """
    Generates card data for a user.
    :return: Dictionaries of card data and hidden card data
    """

    card_number, hidden_card_number = _generate_card_number()
    cvc, hidden_cvc = _generate_random_cvc()
    expiry_date, hidden_expiry_date = _generate_expiry_date()

    card_dict = {
        'number': card_number,
        'cvc': cvc,
        'expiry_date': expiry_date
    }

    hidden_card_dict = {
        'number': hidden_card_number,
        'cvc': hidden_cvc,
        'expiry_date': hidden_expiry_date
    }

    return card_dict, hidden_card_dict


def _generate_card_number() -> (str, str):
    """
    Generates a random VISA card number.
    VISA card format: 4XXXXXXXXXXXXXXX (16 digits)

    :returns: generated card number unique to the database, hidden card number
    """

    visa_prefix = '4'
    card_number = visa_prefix + ''.join(str(random.randint(0, 9)) for _ in range(15))

    checksum = _generate_luhn_checksum(card_number)
    card_number += str(checksum)

    hidden_card_number = _hide_card_number(card_number)

    return card_number, hidden_card_number


def _hide_card_number(card_number: str) -> str:
    """
    Hides the middle part of a card number with asterisks.

    :param card_number: Card number to hide.
    :returns: Card number with the middle part hidden.
    """

    return card_number[:4] + '*' * 8 + card_number[-4:]


def _generate_luhn_checksum(card_number: str) -> int:
    """
    Generates a checksum for a card number using the Luhn algorithm.

    :param card_number: Number to generate checksum for as a string.
    :returns: generated checksum as an integer.
    """

    digits = [int(digit) for digit in card_number]
    odd_digits = digits[-2::-2]
    even_digits = [2 * int(digit) if int(digit) < 5 else 2 * int(digit) - 9 for digit in digits[-1::-2]]

    total = sum(odd_digits + even_digits) % 10
    return (10 - total) % 10


def _generate_random_cvc() -> (str, str):
    """
    Generates a random CVC code.
    CVC code format: XXX (3 digits)

    :returns: generated CVC code
    """

    random_cvc = ''.join(str(random.randint(0, 9)) for _ in range(3))
    hidden_cvc = '*' * 3

    return random_cvc, hidden_cvc


def _generate_expiry_date() -> (str, str):
    """
    Generates expiry date for a card.
    :return: Expiry date in format MM/YY, hidden expiry date in format **/**
    """
    card_expiry_years = 3
    current_millenium = 2000  # TODO: Change in 2100

    month = datetime.datetime.now().month
    year = datetime.datetime.now().year - current_millenium + card_expiry_years

    padded_month = f'0{month}' if month < 10 else f'{month}'
    padded_year = f'0{year}' if year < 10 else f'{year}'

    expiry_date = f'{padded_month}/{padded_year}'
    hidden_expiry_date = '**/**'

    return expiry_date, hidden_expiry_date


def generate_random_consecutive_numbers(max_length, amount_of_nums_to_generate) -> list[int]:
    """
    Generates a list of random consecutive numbers.

    :param max_length: Maximum number to generate.
    :param amount_of_nums_to_generate: Amount of numbers to generate.
    :return: List of random consecutive numbers in range [1, max_length].
    """

    if amount_of_nums_to_generate > max_length:
        raise ValueError("Amount of numbers generated cannot be greater than max length")

    numbers = set()
    while len(numbers) < amount_of_nums_to_generate:
        number = random.randint(1, max_length)
        numbers.add(number)

    return sorted(list(numbers))


def generate_random_password_recovery_code():
    """
    Generates a random password recovery code.

    :return: Random password recovery code.
    """
    # TODO: Take value from config
    PASSWORD_RECOVERY_CODE_LENGTH = 32

    return secrets.token_hex(PASSWORD_RECOVERY_CODE_LENGTH)
