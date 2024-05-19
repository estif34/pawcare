from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField,Form,validators
from wtforms.validators import DataRequired, Email, EqualTo, Length

bcrypt = Bcrypt()
db = SQLAlchemy()

# Create owner model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Fullname = db.Column(db.String(250),nullable=False)
    Email = db.Column(db.String(250), unique=True,nullable=False)
    Password = db.Column(db.String(250),nullable=False)
    
    def __init__(self,Fullname,Email,Password):
        self.Fullname = Fullname
        self.Email = Email
        self.Password = bcrypt.generate_password_hash(Password).decode('utf-8')

# Registration form
class RegistrationForm(Form):
    Fullname = StringField('Fullname', validators=[Length(min=2, max=20)])
    Email = StringField('Email', [validators.Length(min=6, max=35)])
    Password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    Confirm_Password = PasswordField('Confirm_Password', validators=[DataRequired(), EqualTo('Password', message="Passwords must match")])
    # submit = SubmitField('Create Account')