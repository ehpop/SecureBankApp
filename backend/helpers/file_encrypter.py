from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


def get_secure_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Returns a secure key from a password and salt.
    :param password: Password to be used to generate the key
    :param salt: Salt to be used to generate the key (bytes)
    :return: Generated key (bytes)
    """
    return PBKDF2(password, salt, dkLen=32)


def encrypt_bytes_with_password_and_salt(file_content: bytes, password: str, salt: bytes) -> bytes:
    """
    Encrypts a file content with a password and salt.
    :param file_content: File content to be encrypted (bytes)
    :param password: File password (string)
    :param salt: Salt to be used to generate the key (bytes)
    :return: Encrypted file content (bytes)
    """
    key = get_secure_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(file_content, AES.block_size))
    iv = cipher.iv

    return iv + ciphertext


def decrypt_bytes_with_password_and_salt(file_content: bytes, password: str, salt: bytes) -> bytes:
    """
    Decrypts a file content with a password and salt.
    :param file_content: File content to be decrypted (bytes)
    :param password: Password to be used to generate the key (string)
    :param salt: Salt to be used to generate the key (bytes)
    :return: Decrypted file content (bytes)
    """
    key = get_secure_key_from_password(password, salt)
    iv = file_content[: AES.block_size]
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(
        decrypt_cipher.decrypt(file_content[AES.block_size:]), AES.block_size
    )

    return plaintext
