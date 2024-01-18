from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import PasswordField, SubmitField


class SendDocumentForm(FlaskForm):
    file = FileField(validators=[FileRequired(), FileAllowed(['jpg', 'png', 'jpeg', 'pdf'],
                                                             'Only these formats allowed: jpg, png, jpeg, .pdf!')])
    password = PasswordField('Password')
    submit = SubmitField('Upload')
