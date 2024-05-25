from flask import Flask, render_template,session,redirect,abort, request,flash,g,url_for
from google_auth_oauthlib.flow import Flow
from flask_mail import Mail,Message
from flask_login import LoginManager, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash
from models import Users,RegistrationForm,db,LoginForm,ResetPassForm
from random import *
import pathlib,os
from flask_bcrypt import Bcrypt
from pathlib import Path
from bcrypt import hashpw, gensalt

bcrypt = Bcrypt()

app = Flask(__name__)

app.secret_key = "MyGoogleSAuth"

def set_password(self, Password):
        self.password_hash = hashpw(Password.encode('utf-8'), gensalt()).decode('utf-8')

otp =randint(000000,999999)

login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///owners.db"

db.init_app(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'iamhawiana@gmail.com'
app.config['MAIL_PASSWORD'] = 'ycgtkqjlzfxanlsb'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.secret_key = 'myfishsucksmiamiaa'
mail = Mail(app)


GOOGLE_CLIENT_ID = ""
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file,  # Path to the client_secret.json file
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/home"
)


@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

# ROUTES 
@app.route("/")
def landing_page():
    # flash('Login successful!', 'success') 
    return render_template ("landing.html")

@app.route('/auth-checker/<otp>', methods=["GET","POST"])
def checker(otp):
    if request.method == "POST":
        code = request.form["user-otp"]
        if code == str(otp):
            # flash("Account created", "success")
            return render_template("forms/reset-password.html") 
        else:
            flash('Invalid otp',otp=otp)
    
    return ("error")

@app.route('/home', methods=["GET","POST"])
def home():
    return render_template("home.html")


@app.route('/login', methods=["GET","POST"])
def login():
    Logform = LoginForm()
    if Logform.validate_on_submit():
        user = Users.query.filter_by(Email=Logform.Email.data).first()
        login_user(user)

        return render_template('home.html')  # Redirect to landing instead of render_template
   

    return render_template("forms/SignIn.html", Logform=Logform)

@app.route('/register', methods=["GET","POST"])
def register():
    Regform = RegistrationForm()
    if Regform.validate_on_submit():
         #   user = Users.query.filter_by(Email=Regform.Email.data).first()
            user = Users(Fullname=Regform.Fullname.data, Email=Regform.Email.data, Password=Regform.Password.data)
            db.session.add(user)
            db.session.commit()

            #Send email with mail credentials at the top
            otp_str = str(otp)
            Email = request.form['Email']
            EmailContent = render_template("email.html", otp=otp_str)
            msg = Message(subject="Welcome to PetCo", sender='iamhawiana@gmail.com', recipients=[Email])
            msg.html = EmailContent

            mail.send(msg)   

            flash('Email has been sent your account', 'primary')
            return render_template ('verify.html', otp=otp) 
    # else:
    #     flash('Invalid email or password', 'danger')


    return render_template("forms/SignUp.html", Regform = Regform)


@app.route('/reset', methods=["GET","POST"])
def reset():
    if current_user.is_authenticated:
        if request.method == "POST":
            word = request.form['New_Password']
            new1 = request.form['Confirm_Password']  
            print(word)
            print(new1)
            # new_password = form.New_Password.data
            if word == new1:
                current_user.Password = current_user.set_password(word)
                db.session.commit()
                return "HIII"
            else:
                flash("Password not match")
            # return "Password reset successfully"
        else:
            flash("Not validating",'danger')
    else:
        return redirect(url_for('login'))
                
    return render_template("forms/reset-password.html")

@app.route('/forgot', methods=["GET","POST"])
def forgot():
    return render_template("forms/forgot-password.html")

@app.route('/verify', methods=["GET","POST"])
def tryi():
    return render_template("verify.html")

@app.route("/auth", methods=["GET", "POST"])
def autho():
    return render_template("forms/SignIn.html")


# Google account lists display 
@app.route("/google_auth")
def authenticate():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    print(state)
    return redirect (authorization_url)

@app.route("/logout")
def logout():
    session.clear()
    return redirect (url_for("landing_page"))


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)

