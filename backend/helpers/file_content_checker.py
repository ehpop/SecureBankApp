from typing import IO

import PIL.Image
from PIL import Image
from pypdf import PdfReader
from pypdf.errors import PdfReadError


def check_pdf_content(bytes_stream: IO[bytes]) -> bool:
    """
    Check if the file content is a valid pdf
    :param bytes_stream: file content as bytes stream
    :return: True if the file content is a valid pdf, False otherwise
    """
    try:
        PdfReader(bytes_stream)
    except PdfReadError:
        return False

    return True


def check_image_content(bytes_stream: IO ) -> bool:
    """
    Check if the file content is a valid image
    :param bytes_stream: file content as bytes stream
    :return: True if the file content is a valid image, False otherwise
    """
    try:
        Image.open(bytes_stream)
    except PIL.Image.DecompressionBombWarning:
        # TODO: Add error handling for decompression bomb warning
        # f'Image is too large, max amount of pixels is {PIL.Image.MAX_IMAGE_PIXELS} pixels'
        return False
    except:
        return False

    return True

def check_file_content_based_on_extension(file_content: IO[bytes], file_extension: str) -> bool:
    """
    Check if the file content is valid based on the file extension
    :param file_content: file content in bytes
    :param file_extension: file extension
    :return: True if the file content is valid, False otherwise
    """
    if file_extension in ['.pdf']:
        return check_pdf_content(file_content)
    elif file_extension in ['.jpg', '.jpeg', '.png']:
        return check_image_content(file_content)
    else:
        return False

def get_file_extension(filename: str) -> str:
    """
    Get the file extension from a filename
    :param filename
    :return: file extension
    """
    return '.' + filename.rsplit('.', 1)[1].lower()