import random


def generate_account_number() -> str:
    """
    Generates a random Polish IBAN number.
    PL IBAN format: PLXX XXXX XXXX XXXX XXXX XXXX XXXX
    'PL' (2 characters) + 24 digits

    :returns: generated account number unique to the database
    """

    pl_iban = 'PL' + ''.join(str(random.randint(0, 9)) for _ in range(24))

    return pl_iban


def generate_card_number() -> str:
    """
    Generates a random VISA card number.
    VISA card format: 4XXXXXXXXXXXXXXX (16 digits)

    :returns: generated card number unique to the database
    """

    visa_prefix = '4'
    card_number = visa_prefix + ''.join(str(random.randint(0, 9)) for _ in range(15))

    checksum = generate_luhn_checksum(card_number)
    card_number += str(checksum)

    return card_number


def generate_luhn_checksum(card_number: str) -> int:
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
