import wtforms
from flask_wtf import FlaskForm


class AccessDocumentForm(FlaskForm):
    password = wtforms.PasswordField('Password', validators=[wtforms.validators.DataRequired(),
                                                             wtforms.validators.Length(min=8, max=16)])
    submit = wtforms.SubmitField('Access document')
