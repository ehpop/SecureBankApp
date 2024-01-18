from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginWithPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=16)])
    submit = SubmitField('Login')
