from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp

from backend.forms.shared.regex import password_regex


class SetNewPasswordForm(FlaskForm):
    new_password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=16),
                                                         Regexp(password_regex,
                                                                message="Password must contain at least 1 uppercase letter, 1 number and 1 special character."),
                                                         EqualTo('repeat_new_password',
                                                                 message='New passwords must match')])
    repeat_new_password = PasswordField('Repeat password', validators=[DataRequired(), Length(min=8, max=16)])

    submit = SubmitField('Set new password')
