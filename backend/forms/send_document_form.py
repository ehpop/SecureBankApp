from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import PasswordField, SubmitField

from shared.regex import password_regex


class SendDocumentForm(FlaskForm):
    file = FileField(validators=[FileRequired(), FileAllowed(['jpg', 'png', 'jpeg', 'pdf'],
                                                             'Only these formats allowed: jpg, png, jpeg, .pdf!')])
    password = PasswordField('Password', Regex(password_regex,
                                               message="Password must contain at least 1 uppercase letter, 1 number and 1 special character."))
    submit = SubmitField('Upload')
