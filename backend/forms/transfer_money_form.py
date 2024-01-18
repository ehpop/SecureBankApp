from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange, Regexp

"""
Account must be polish IBAN number.
"""
iban_regex = "^PL[0-9]{26}$"


class TransferMoneyForm(FlaskForm):
    transfer_title = StringField('Transfer title', validators=[DataRequired(), Length(min=2, max=20)])
    account_to_transfer = StringField('Account to transfer', validators=[DataRequired(), Length(min=28, max=28),
                                                                         Regexp(iban_regex,
                                                                                message="Account must be polish IBAN number.")])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=1, max=100_000)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=16)])

    submit = SubmitField('Transfer')
