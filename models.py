from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, Form, validators, FileField, HiddenField, IntegerField, SelectField, DateTimeField, DateField, TimeField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_wtf.file import FileAllowed
import re

db = SQLAlchemy()
bcrypt = Bcrypt()

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Fullname = db.Column(db.String(250), nullable=False)
    Email = db.Column(db.String(250), unique=True, nullable=False)
    Password = db.Column(db.String(250), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # Added role field
    profile_picture = db.Column(db.String(250), nullable=True)
    pets = db.relationship('Pet', backref='owner', lazy=True)


    def __init__(self, Fullname, Email, Password, role):
        self.Fullname = Fullname
        self.Email = Email
        self.Password = self.set_password(Password)
        self.role = role

    def check_password(self, Password):
        return bcrypt.check_password_hash(self.Password, Password)

    def set_password(self, Password):
        return bcrypt.generate_password_hash(Password).decode('utf-8')
    

class Pet(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    species = db.Column(db.String(250), nullable=False)
    breed = db.Column(db.String(250), nullable=True)
    age=db.Column(db.Integer, nullable=True)
    profile_photo = db.Column(db.String(250), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


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
    
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pet_id = db.Column(db.Integer, db.ForeignKey('pet.id'), nullable=False)
    vet_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='scheduled')

    pet = db.relationship('Pet', backref='appointments', lazy=True)
    vet = db.relationship('Users', foreign_keys=[vet_id], backref='vet_appointments', lazy=True)
    owner = db.relationship('Users', foreign_keys=[owner_id], backref='owner_appointments', lazy=True)


class RegistrationForm(FlaskForm):
    Fullname = StringField('Fullname', validators=[DataRequired()])
    Email = StringField('Email', [Email()])
    Password = PasswordField('Password', validators=[Length(min=6)])
    Confirm_Password = PasswordField('Confirm_Password', validators=[DataRequired()])
    role = HiddenField('Role', default='user')
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
    Email = StringField('Email', validators=[DataRequired(), Email()])
    Password = PasswordField('Password', validators=[DataRequired()])
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


class ProfileForm(FlaskForm):
    Fullname = StringField('Fullname', validators=[DataRequired()])
    Email = StringField('Email', [Email()])
    profile_picture = FileField('Profile Picture')
    Submit = SubmitField('Update Profile')

class PetForm(FlaskForm):
    name = StringField('Pet Name', validators=[DataRequired()])
    species = StringField('Species', validators=[DataRequired()])
    breed = StringField('Breed')
    age = IntegerField('Age')
    profile_photo = FileField('Profile Photo', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Submit Pet')

class AppointmentForm(FlaskForm):
    Pet = SelectField('Pet', validators=[DataRequired()])
    vet = SelectField('Veterinarian', validators=[DataRequired()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()])
    time = TimeField('Time', format='%H:%M', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Book Appointment')

class RescheduleAppointmentForm(FlaskForm):
    date = DateField('New Date:', format="%Y-%m-%d", validators=[DataRequired()])
    time = TimeField('New Time', format='%H:%M', validators=[DataRequired()])
    submit = SubmitField('Reschedule Appointment')

class CancelAppointmentForm(FlaskForm):
    submit = SubmitField('Cancel Appointment')

class AdminRegistrationForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = Users.query.filter_by(Email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Please choose a different one.')

class EditVetForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    status = StringField('Status', validators=[DataRequired()])
    submit = SubmitField('Update')

class EditUserForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')
