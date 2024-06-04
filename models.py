from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, Form, validators
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Fullname = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)

    def __init__(self, Fullname, Email, Password):
        self.Fullname = Fullname
        self.Email = Email
        self.Password = self.set_password(Password)

    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    

class Pets(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    PetName = db.Column(db.String(250), nullable=False)
    Species = db.Column(db.String(250), unique=True, nullable=False)
    OwnerId = db.Column(db.Integer, nullable=False)


class Vets(UserMixin, db.Model):
    VetId = db.Column(db.Integer, primary_key=True)
    VetName = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)

    def __init__(self, Fullname, Email, Password):
        self.Fullname = Fullname
        self.Email = Email
        self.Password = self.set_password(Password)

    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')

class RegistrationForm(FlaskForm):
    Fullname = StringField('Fullname', validators=[DataRequired()])
    Email = StringField('Email', [Email()])
    Password = PasswordField('Password', validators=[Length(min=6)])
    Confirm_Password = PasswordField('Confirm_Password', validators=[DataRequired()])
    Submit = SubmitField('Create_Account')

    def validate_Email(self, field):
        if Users.query.filter_by(Email=field.data).first():
            raise ValidationError('Email already exists')

    def validate_Password(self, field):
        if field.data != self.Confirm_Password.data: 
            raise ValidationError('Passwords must match')
        else:
            if not re.search(r"[A-Z]", field.data):
                raise ValidationError('Password must contain at least one uppercase letter.')
            else:
                if not re.search(r"[0-9]", field.data):
                    raise ValidationError('Password must contain at least one number.')

class LoginForm(FlaskForm):
    Email = StringField('Email')
    Password = PasswordField('Password')
    Submit = SubmitField('Login')

    def validate_Email(self, field):
        if not Users.query.filter_by(Email=field.data).first():
            raise ValidationError('Invalid email')

    def validate_Password(self, field):
        user = Users.query.filter_by(Email=self.Email.data).first()
        if not user or not user.check_password(field.data):
            raise ValidationError('Invalid password')

# class ResetPassForm(FlaskForm):
#     New_Password =  PasswordField('New_Password')
#     Confirm_Password = PasswordField('Confirm_Password')
#     Submit = SubmitField('Reset')
