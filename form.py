from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Register')
    
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Login')

class FileUploadForm(FlaskForm):
    filename = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "filename"})
    file = FileField(validators=[InputRequired()], name='file')
    submit = SubmitField('upload')
    
class PrivateDataForm(FlaskForm):
    data_name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "data_name"})
    data_isi = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "data"})
    submit = SubmitField('Login')