import pyAesCrypt
import Crypto
import base64
import io
from Crypto.Protocol.KDF import PBKDF2


def get_secure_key_from_password(password, salt) -> str:
    """
    Returns a secure key from a password and salt.
    :param password: Password to be used to generate the key
    :param salt: Salt to be used to generate the key (bytes)
    :return: Generated key (string)
    """
    return base64.b64encode(PBKDF2(password, salt, dkLen=32)).decode("utf-8")


def encrypt_file_content_with_key(file_content: bytes, password, salt) -> bytes:
    """
    Encrypts a file content with a password and salt.
    :param file_content: File content to be encrypted (bytes)
    :param password: File password (string)
    :param salt: Salt to be used to generate the key (bytes)
    :return: Encrypted file content (bytes)
    """
    key = get_secure_key_from_password(password, salt)
    input_stream = io.BytesIO(file_content)
    output_stream = io.BytesIO()
    pyAesCrypt.encryptStream(input_stream, output_stream, key)

    return output_stream.getvalue()


def decrypt_file_content_with_key(file_content: bytes, password, salt) -> bytes:
    """
    Decrypts a file content with a password and salt.
    :param file_content: File content to be decrypted (bytes)
    :param password: Password to be used to generate the key (string)
    :param salt: Salt to be used to generate the key (bytes)
    :return: Decrypted file content (bytes)
    """
    key = get_secure_key_from_password(password, salt)
    input_stream = io.BytesIO(file_content)
    output_stream = io.BytesIO()
    pyAesCrypt.decryptStream(input_stream, output_stream, key)

    return output_stream.getvalue()
