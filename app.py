from flask import Flask, render_template,session,redirect,abort, request,flash,g,url_for, jsonify
from google_auth_oauthlib.flow import Flow
from flask_mail import Mail,Message
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_session import Session
from models import Users,RegistrationForm,db,LoginForm, Vets, Appointment, ProfileForm, Pet, PetForm, AppointmentForm, CancelAppointmentForm, RescheduleAppointmentForm, AdminRegistrationForm, EditVetForm, EditUserForm
from random import *
import pathlib,os, secrets, json
from flask_bcrypt import Bcrypt  
from dotenv import load_dotenv   
from googleapiclient.discovery import build
from pathlib import Path
from bcrypt import hashpw, gensalt
from functools import wraps
from flask_bcrypt import generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, time
from PIL import Image
from sqlalchemy import func


load_dotenv()
bcrypt = Bcrypt()
otp =randint(000000,999999)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///owners.db"

db.init_app(app)

# APP CONFIGURATIONS
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
# app.secret_key = "XXX"
app.config['SESSION_FILE_DIR'] = os.path.join(app.root_path, "sessions")
app.config['SESSION_FILE_THRESHOLD'] = 1000
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
mail = Mail(app)
# Session(app)


# GOOGLE CONFIGURATIONS
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
#

# def set_password(self, Password):
#     self.password_hash = hashpw(Password.encode('utf-8'), gensalt()).decode('utf-8')

def set_password(Password):
    return bcrypt.generate_password_hash(Password).decode('utf-8')
        
# SESSIONS MANAGER
@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

# ROUTES 
@app.route("/")
def landing_page():
    # flash('Login successful!', 'success') 
    return render_template ("landing.html")

@app.route('/homee', methods=["GET","POST"])
def home():
    return render_template("home.html")

# LOGIN USER
@app.route('/login', methods=["GET","POST"])
def login():
    Logform = LoginForm()
    if Logform.validate_on_submit():
        user = Users.query.filter_by(Email=Logform.Email.data).first()
        if user and user.check_password(Logform.Password.data):
            # login_user(user)
            # otp_str = str(otp)
            # Email = Logform.Email.data
            # EmailContent = render_template("emails/log-otp-email.html", otp=otp_str)
            # msg = Message(subject="Welcome back!", sender='stephengm31@gmail.com', recipients=[Email])
            # msg.html = EmailContent

            # mail.send(msg)   
            login_user(user)
            # flash('Email has been sent your account', 'primary')
            # return render_template ('login-verify.html', otp=otp)
            return render_template("home.html") #reset-password.html
 
        else:
            flash('Invalid email or password', 'danger')
        #return render_template('home.html')  # Redirect to landing instead of render_template

    return render_template("forms/SignIn.html", Logform=Logform)

@app.route('/login-check/<otp>', methods=["GET","POST"])
def logchecker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("home.html") #reset-password.html
        else:
            flash ('invalid otp','danger')


# REGISTER USER
@app.route('/register', methods=["GET","POST"])
def register():
    Regform = RegistrationForm()
    if Regform.validate_on_submit():
            #flash('Password must contain a number[0-9], characters(!,$) and a capital letter ', 'primary')
            user = Users(Fullname=Regform.Fullname.data, Email=Regform.Email.data, Password=Regform.Password.data, role=Regform.role.data)
            Fullname=Regform.Fullname.data
            # session['reset_email'] = Email
            fullname= session.get('Fullname')
            
            db.session.add(user)
            db.session.commit()

            #Send email with mail credentials at the top
            otp_str = str(otp)
            Email = request.form['Email']
            EmailContent = render_template("emails/email.html", otp=otp_str)
            msg = Message(subject="Welcome to PetCo", sender='stephengm31@gmail.com', recipients=[Email])
            msg.html = EmailContent

            mail.send(msg)   
            login_user(user)
            flash('Email has been sent your account', 'primary')
            return render_template ('verify.html', otp=otp) 


    return render_template("forms/SignUp.html", Regform = Regform)

@app.route('/auth-checker/<otp>', methods=["GET","POST"])
def checker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("forms/reset-password.html") #reset-password.html
        else:
            return('invalid otp','danger')
    
    return ("error")

@app.route('/forgot-pass', methods=["GET","POST"])
def display():
    return render_template('forms/email-otp.html')


@app.route('/verify-otp')
def dis():
    return render_template('forms/otp.html')


#FORGOT PASSWORD AND RESET
@app.route('/reset', methods=["GET","POST"])
def reset(): 
    if request.method == "POST":
        Email = request.form['Email']
        # Email = session.get('reset_email')
        Password = request.form['New_Password']
        New_Password = request.form['Confirm_Password']  
        user = Users.query.filter_by(Email=Email).first()
        #user = Users.query.filter_by(Email=self.Email.data).first()
        if Password == New_Password:
            user.Password = bcrypt.generate_password_hash(Password).decode('utf-8')
            db.session.commit()
            flash("Password updated successfully!", "primary")
            return redirect(url_for("login"))
                
        else:
            flash("Password not match")
            return redirect(url_for('login'))
    else:
            flash("Not validating",'danger')
                
    return render_template("forms/reset-password.html")


@app.route('/reset-email', methods=["GET","POST"])
def res_email():
    if request.method=="POST":
        Email = request.form['Email']
        session['reset_email'] = Email
        otp_str = str(otp)
        print(Email)
        EmailContent = render_template("emails/reset-email.html", otp=otp_str)
        msg = Message(subject="Reset Password Confirmation", sender='stephengm31@gmail.com', recipients=[Email])
        msg.html = EmailContent
        print(otp)
        mail.send(msg)   
        flash('Email has been sent to your account', 'primary')
        return render_template('forms/otp.html')
   
    return render_template("forms/reset-pass.html")

@app.route('/conf_password', methods=["GET","POST"])
def cdonf():
    if request.method == "POST":
        auth = request.form["user-otp"]
        print(auth)
    return render_template('forms/forgot-password.html')

@app.route('/forgot', methods=["GET","POST"])
def forgot():
    return render_template("forms/forgot-password.html")

@app.route('/verify', methods=["GET","POST"])
def tryi():
    return render_template("verify.html")

@app.route("/auth", methods=["GET", "POST"])
def autho():
    return render_template("forms/SignIn.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect (url_for("login"))

def check_password(plain_password, Password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), Password)

def verify_password(input_password, Password):
    return bcrypt.check_password_hash(Password, input_password)

@app.route('/lock-session', methods=['GET', 'POST'])
def checkPass():
    Email = session.get('reset_email')
    if request.method == 'POST':
        password = request.form['Password']
        user_id = session.get('_user_id')
        if user_id:   
            user = Users.query.filter_by(id=user_id).first()
            if user and verify_password(password, user.Password):
                return redirect(url_for('home'))
        flash('Invalid password', 'danger')
    return render_template("forms/lock-sesh.html")

# EVERYTHING GOOGLE


# REGISTER WITH GOOGLE 
flow = Flow.from_client_secrets_file(
    client_secrets_file,  # Path to the client_secret.json file
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/home"
)

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}

@app.route('/google-checker/<otp>', methods=["GET","POST"])
def goog_checker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("home.html") 
        else:
            flash('Invalid otp')
    
    return ("error")

# Google account lists display 
@app.route("/google_auth")
def authenticate():
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session["state"] = state
    return redirect(authorization_url)

@app.route("/home")
def google_auth_callback():
    #flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(client_secrets_file, scopes=SCOPES)
    flow.redirect_uri = url_for('google_auth_callback', _external=True)
    authorization_response = request.url

    # Use authorisation code to request credentials from Google
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Use the credentials to obtain user information and save it to the session
    oauth2_client = build('oauth2','v2',credentials=credentials)
    user_info= oauth2_client.userinfo().get().execute()
    session['user'] = user_info
    print (user_info)

    user = Users(Fullname=user_info["name"], Email=user_info["email"], Password="dummyinfo")
    db.session.add(user)
    db.session.commit()

    # Return to main page
    return render_template("home.html")


# LOGIN WITH GOOGLE

flow = Flow.from_client_secrets_file(
    client_secrets_file,  # Path to the client_secret.json file
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=["http://127.0.0.1:5000/callback"],
)

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}

@app.route("/authorize")
def logauthorize():
    # Intiiate login request
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    return redirect(authorization_url)

## Used by Google OAuth
@app.route("/callback")
def callback():
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_response = request.url
    # Use authorisation code to request credentials from Google
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Use the credentials to obtain user information and save it to the session
    oauth2_client = build('oauth2','v2',credentials=credentials)
    user_info= oauth2_client.userinfo().get().execute()
    session['user'] = user_info

    if Users.query.filter_by(Email=user_info['email']).first():
        #flash("Not registered in the database", "danger")

        otp_str = str(otp)
        Email = user_info['email']
        EmailContent = render_template("emails/google-email.html", otp=otp_str)
        msg = Message(subject="Welcome to PetCo", sender='PetCo', recipients=[Email])
        msg.html = EmailContent

        mail.send(msg)   

        # flash('OTP has been sent your account', 'primary')
        # return render_template ('google-otp.html', otp=otp) 
        return render_template('home.html')
    else:
        flash("Account does not exist","danger")
        return redirect(url_for('register'))

    return render_template("landing.html")

@app.route('/reg-reset',methods=["GET","POST"])
def newreset():
    if current_user.is_authenticated:
        if request.method == "POST":
            p1 = request.form['New_Password']
            p2 = request.form['Confirm_Password']  
            if p1 == p2:
                current_user.Password = current_user.set_password(p1)
                db.session.commit()
                return redirect(url_for('login'))
            else:
                flash("Password not match")
            # return "Password reset successfully"
        else:
            flash("Not validating",'danger')
    else:
        return redirect(url_for('login'))

@app.route('/create_admin')
def create_admin():
    admin_email = "estifanos.gebremedhin@strathmore.edu"  # Replace with your admin email
    admin_password = os.getenv('ADMIN_1_PASSWORD')
    
    admin = Users(Fullname="Admin User", Email=admin_email, Password=admin_password, role="admin")
    db.session.add(admin)
    db.session.commit()
    return "Admin user created!"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('landing_page'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/veterinarians', methods=['GET', 'POST'])
@admin_required
def manage_veterinarians():
    if request.method == 'POST':
        veterinarian_id = request.form.get('veterinarian_id')
        action = request.form.get('action')

        veterinarian = Users.query.get(veterinarian_id)
        if action == 'approve':
            veterinarian.role = 'veterinarian'
        elif action == 'reject':
            db.session.delete(veterinarian)
        db.session.commit()

    veterinarians = Users.query.filter_by(role='pending_veterinarian').all()
    return render_template('admin/manage_veterinarians.html', veterinarians=veterinarians)

@app.route('/register_veterinarian', methods=['GET', 'POST'])
@login_required
def register_veterinarian():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        veterinarian = Users(Fullname=form.fullname.data, Email=form.email.data, Password=form.password.data, role='veterinarian')
        db.session.add(veterinarian)
        db.session.commit()
        flash('Veterinarian account has been created!', 'success')
        return redirect(url_for('home'))
    
    return render_template('admin/register_veterinarian.html', form=form)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.route('/profile', methods = ['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.Fullname = form.Fullname.data
        current_user.Email = form.Email.data

        if form.profile_picture.data:
            filename = secure_filename(form.profile_picture.data.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.profile_picture.data.save(filepath)
            current_user.profile_picture = filepath

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)

@app.route('/register_pet', methods=['GET', 'POST'])
@login_required
def register_pet():
    form = PetForm()
    if form.validate_on_submit():
        if form.profile_photo.data:
            photo_file = save_picture(form.profile_photo.data)
        else:
            photo_file = None
        pet = Pet(
            name=form.name.data,
            species=form.species.data,
            breed=form.breed.data,
            age=form.age.data,
            profile_photo=photo_file,
            owner_id=current_user.id
        )
        db.session.add(pet)
        db.session.commit()
        flash('Pet registered successfully!', 'success')
        return redirect(url_for('my_pets'))
    return render_template('register_pet.html', form=form)

@app.route('/update_pet/<int:pet_id>', methods=['GET', 'POST'])
@login_required
def update_pet(pet_id):
    pet = Pet.query.get_or_404(pet_id)
    form=PetForm()
    if form.validate_on_submit():
        pet.name = form.name.data
        pet.species = form.species.data
        pet.breed = form.breed.data
        if form.profile_photo.data:
            photo_file = save_picture(form.profile_photo.data)
            pet.profile_photo = photo_file
        db.session.commit()
        flash('Your pet\'s profile has been updated!', 'success')
        return redirect(url_for('my_pets'))
    elif request.method == 'GET':
        form.name.data = pet.name
        form.species.data = pet.species
    return render_template('update_pet.html', form=form, pet=pet)

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/pet_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


def send_mail_notification(recipient, subject, template, context):
    msg = Message(
        subject,
        sender='stephengm31@gmail.com',
        recipients=[recipient]
    )
    msg.html = render_template(template, **context)
    mail.send(msg)

@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    form = AppointmentForm()
    form.Pet.choices = [(Pet.id, Pet.name) for Pet in Pet.query.filter_by(owner_id=current_user.id).all()]
    form.vet.choices = [(Users.id, Users.Fullname) for Users in Users.query.filter_by(role='veterinarian').all()]#, status='approved').all()]

    if form.validate_on_submit():
        appointment_datetime = datetime.combine(form.date.data, form.time.data)
        appointment = Appointment(
            pet_id = form.Pet.data,
            vet_id = form.vet.data,
            owner_id=current_user.id,
            date=appointment_datetime,
            description=form.description.data
        )
        db.session.add(appointment)
        db.session.commit()

        send_mail_notification(
            recipient=current_user.Email,
            subject='Appointment Booked',
            template='emails/appointment_booked.html',
            context={'appointment': appointment}
        )

        flash('Appointment booked successfully!', 'success')
        return redirect(url_for('my_appointments'))

    return render_template('book_appointment.html', form=form)

@app.route('/reschedule_appointment/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def reschedule_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.owner_id != current_user.id: #and appointment.vet_id != current_user.id
        flash('You are not authorized to reschedule this appointment.', 'danger')
        return redirect(url_for('profile'))
    
    form = RescheduleAppointmentForm()
    if form.validate_on_submit():
        appointment_datetime = datetime.combine(form.date.data, form.time.data)
        appointment.date = appointment_datetime
        db.session.commit()

        send_mail_notification(
            recipient=current_user.Email,
            subject='Appointment Rescheduled',
            template='emails/appointment_rescheduled.html',
            context={'appointment': appointment}
        )

        flash('Appointment rescheduled successfully!', 'success')
        return redirect(url_for('my_appointments'))
    
    return render_template('reschedule_appointment.html', form=form, appointment=appointment)

@app.route('/cancel_appointment/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
def cancel_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.owner_id != current_user.id: #and appointment.vet_id != current_user.id
        flash('You are not authorized to cancel this appointment.', 'danger')
        return redirect(url_for('profile'))
    
    form = CancelAppointmentForm()
    if form.validate_on_submit():
        appointment.status = 'cancelled'
        db.session.commit()

        send_mail_notification(
            recipient=current_user.Email,
            subject='Appointment Cancelled',
            template='emails/appointment_cancelled.html',
            context={'appointment': appointment}
        )

        flash('Appointment cancelled successfully!', 'success')
        return redirect(url_for('my_appointments'))
    
    return render_template('cancel_appointment.html', form=form, appointment=appointment)

@app.route('/my_pets')
@login_required
def my_pets():
    pets = current_user.pets
    return render_template('my_pets.html', pets=pets)

@app.route('/my_appointments')
@login_required
def my_appointments():
    appointments = current_user.owner_appointments
    return render_template('my_appointments.html', appointments=appointments)

# @app.route('/appointments')
# @login_required
# def appointments():
#     appointments = Appointment.query.all()
#     appointments_list = json.dumps([{
#         'pet_name': appointment.pet.name,
#         'vet_name': appointment.vet.Fullname,
#         'date': appointment.date.isoformat(),
#         'description': appointment.description,
#         'url': url_for('reschedule_appointment', appointment_id=appointment.id)
#     } for appointment in appointments if appointment.status == "scheduled"])
#     appointments_json = json.dumps(appointments_list)
#     return render_template('my_appointments.html', appointments=appointments_json)

@app.route('/register_admin', methods=['GET', 'POST'])
@login_required
def register_admin():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        admin = Users(Fullname=form.fullname.data, Email=form.email.data, Password=form.password.data, role='admin')
        db.session.add(admin)
        db.session.commit()
        flash('Admin account has been created!', 'success')
        return redirect(url_for('home'))
    
    return render_template('register_admin.html', form=form)

@app.route('/manage_vets', methods=['GET', 'POST'])
@login_required
def manage_vets():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))
    
    vets = Users.query.filter_by(role='veterinarian').all()
    return render_template('manage_vets.html', vets=vets)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))
    
    users = Users.query.filter_by(role='user').all()
    return render_template('manage_users.html', users=users)

@app.route('/edit_vet/<int:vet_id>', methods=['GET', 'POST'])
@login_required
def edit_vet(vet_id):
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))

    vet = Users.query.get_or_404(vet_id)
    form = EditVetForm()
    if form.validate_on_submit():
        vet.Fullname = form.fullname.data
        vet.Email = form.email.data
        vet.status = form.status.data
        db.session.commit()
        flash('Veterinarian details have been updated!', 'success')
        return redirect(url_for('manage_vets'))
    
    elif request.method == 'GET':
        form.fullname.data = vet.Fullname
        form.email.data = vet.Email
        # form.status.data = vet.status
    
    return render_template('edit_vet.html', form=form)

@app.route('/delete_vet/<int:vet_id>', methods=['GET', 'POST'])
@login_required
def delete_vet(vet_id):
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))

    vet = Users.query.get_or_404(vet_id)
    db.session.delete(vet)
    db.session.commit()
    flash('Veterinarian account has been deleted!', 'success')
    return redirect(url_for('manage_vets'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))

    user = Users.query.get_or_404(user_id)
    form = EditUserForm()
    if form.validate_on_submit():
        user.Fullname = form.fullname.data
        user.Email = form.email.data
        db.session.commit()
        flash('User details have been updated!', 'success')
        return redirect(url_for('manage_users'))
    
    elif request.method == 'GET':
        form.fullname.data = user.Fullname
        form.email.data = user.Email
    
    return render_template('edit_user.html', form=form)

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('home'))

    user = Users.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User account has been deleted!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/vet/appointments')
@login_required
def vet_appointments():
    if current_user.role != 'veterinarian':
        abort(403)
    return render_template('vet_appointments.html')

@app.route('/vet/appointments/data')
@login_required
def vet_appointments_data():
    if current_user.role != 'veterinarian':
        abort(403)
    appointments =Appointment.query.filter_by(vet_id=current_user.id).all()
    events = []
    for appointment in appointments:
        events.append({
            'title': f"{appointment.pet.name} with {appointment.owner.Fullname}",
            'start': appointment.date.isoformat(),
            # 'end':appointment.date.isoformat()
        })
    return jsonify(events)    

# Route to fetch data for the pie chart (appointments by vet)
@app.route('/admin/reports/appointments_by_vet')
@login_required
def appointments_by_vet():
    if current_user.role != 'admin':
        abort(403)  # Forbidden if not an admin

    # Query to get the count of appointments per vet
    appointments_data = db.session.query(
        Users.Fullname, func.count(Appointment.id)
    ).join(Appointment, Users.id == Appointment.vet_id).group_by(Users.Fullname).all()

    data = {
        'labels': [vet for vet, _ in appointments_data],
        'values': [count for _, count in appointments_data]
    }

    return jsonify(data)

# Route to fetch data for the bar chart (counts of pets, vets, and owners)
@app.route('/admin/reports/system_counts')
@login_required
def system_counts():
    if current_user.role != 'admin':
        abort(403)  # Forbidden if not an admin

    pets_count = db.session.query(func.count(Pet.id)).scalar()
    vets_count = db.session.query(func.count(Users.id)).filter_by(role='veterinarian').scalar()
    owners_count = db.session.query(func.count(Users.id)).filter_by(role='user').scalar()

    data = {
        'labels': ['Pets', 'Vets', 'Owners'],
        'values': [pets_count, vets_count, owners_count]
    }

    return jsonify(data)

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.role != 'admin':
        abort(403)  # Forbidden if not an admin
    return render_template('admin/admin_reports.html')





with app.app_context():
    db.create_all()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

if __name__ == "__main__":
    app.run(debug=True)
