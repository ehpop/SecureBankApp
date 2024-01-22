from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp

from backend.forms.shared.regex import password_regex, username_regex


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20), Regexp(username_regex,
                                                                                         message="Username can contain only letters, numbers and underscores.")])
    lastname = StringField('Lastname', validators=[DataRequired(), Length(min=2, max=20)])
    username = StringField('Username', validators=[DataRequired(), Length(min=6, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=16),
                                                     Regexp(password_regex,
                                                            message="Password must contain at least 1 uppercase letter, 1 number and 1 special character."),
                                                     EqualTo('repeat_password', message='Passwords must match')])
    repeat_password = PasswordField('Repeat password', validators=[DataRequired(), Length(min=8, max=16)])

    submit = SubmitField('Register')
