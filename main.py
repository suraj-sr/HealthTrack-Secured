from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm, LoginForm
from datetime import timedelta, datetime
from flask import Flask, request, make_response
from flask_wtf import FlaskForm, RecaptchaField
from password_validation import PasswordPolicy
import hashlib

policy = PasswordPolicy()

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)
app.secret_key = "x{RD/'wutjN87mGN/acnEPSqkS4wp_"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userinfo.db'

app.config["RECAPTCHA_PUBLIC_KEY"] = "6LdRjy8pAAAAAKUExOAkmDtbmg7M144t7aBWu6jW"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LdRjy8pAAAAAGm3w1d3Eryunin0mtDHGkCiUDFa"

db = SQLAlchemy(app)


class User(db.Model):
    recaptcha = RecaptchaField()
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    stats = db.relationship('Stats', backref='owner', lazy=True)

    def __repr__(self) :
        return f"User('{self.username}','{self.email}')"

class Stats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    overall_feeling = db.Column(db.Integer, nullable=False)
    time_slept = db.Column(db.Float, nullable=False)
    worked_out = db.Column(db.Boolean, nullable=False)
    ate_healthy = db.Column(db.String(100), nullable=False)
    time_worked_out = db.Column(db.Integer, nullable=False)
    workout_type = db.Column(db.String(100), nullable=False)
    unhealthy_food = db.Column(db.String(500), nullable=False)
    proud_achievement = db.Column(db.String(2000), nullable=False)

    date_logged = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'''Stats("{self.overall_feeling}", 
                "{self.time_slept}",
                "{self.worked_out}",
                "{self.ate_healthy}",
                "{self.time_worked_out}",
                "{self.workout_type}",
                "{self.unhealthy_food}",
                "{self.proud_achievement}")'''

@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/stats")
def stats():
    # If user is not logged in, redirect to home
    if "username" not in session:
        flash(f'You are not logged in!', 'danger')
        return redirect(url_for('home'))

    # Create table of log entries
    table = list()
    user = User.query.filter_by(username=session["username"]).first()
    
    for entry in user.stats:
        row = list()
        row.append(str(entry.date_logged).split()[0])
        row.append(entry.overall_feeling)
        row.append(entry.time_slept)
        row.append("Yes" if entry.worked_out else "No")
        row.append(entry.ate_healthy)
        row.append(entry.time_worked_out)
        row.append(entry.workout_type)
        row.append(entry.unhealthy_food)
        row.append(entry.proud_achievement)
        table.append(row)

    return render_template("stats.html", table=table[::-1])

@app.route("/graphs")
def graphs():
    # If user is not logged in, redirect to home
    if "username" not in session:
        flash(f'You are not logged in!', 'danger')
        return redirect(url_for('home'))

    # Pulls data from database and send to front end
    user = User.query.filter_by(username=session["username"]).first()

    dates = list()
    sleep = list()
    feelings = list()
    timeWorkedOut = list()
    workedOutBool = [0,0]
    ateHealthy = [0,0,0]
    workoutType = [0, 0, 0]

    for stats in user.stats:

        dates.append(str(stats.date_logged).split()[0])
        timeWorkedOut.append(stats.time_worked_out)
        feelings.append(stats.overall_feeling)
        sleep.append(stats.time_slept)

        if stats.worked_out: workedOutBool[0] += 1
        else: workedOutBool[1] += 1

        if stats.ate_healthy == 'Yes': ateHealthy[0] += 1
        elif stats.ate_healthy == 'No': ateHealthy[1] += 1
        else: ateHealthy[2] += 1

        if 'Strength' in stats.workout_type: workoutType[0] += 1
        if 'Cardio' in stats.workout_type: workoutType[1] += 1 
        if 'Other' in stats.workout_type: workoutType[2] += 1 

    return render_template("graphs.html", dates=dates, feelings=feelings, sleep=sleep, workedOutBool=workedOutBool, 
                            ateHealthy=ateHealthy, timeWorkedOut=timeWorkedOut, workoutType=workoutType)

@app.route("/log_data", methods=['GET', 'POST'])
def log_data():
    # If user is not logged in, redirect to home
    if "username" not in session:
        flash(f'You are not logged in!', 'danger')
        return redirect(url_for('home'))

    # Fires when submit button is pressed
    if request.method == 'POST':

        # Get User Input from HTML Form
        feeling = int(request.form.get('feeling'))
        sleep = float(request.form.get('sleep'))
        worked_out = bool(int(request.form.get('workout')))
        ate_healthy = request.form.get('healthy')
        proud_achievement = request.form.get('proudAchievement')
        time_worked_out = 0 # Default Value - If User did not Workout
        workout_type = "None" # Default Value - If User did not Workout
        unhealthy_food = "None" # Default Value - If User ate Healthy

        # Get workout info if user has worked out
        if (worked_out):
            time_worked_out = int(request.form.get('workoutTime'))
            if len(request.form.getlist('workoutType')) == 0: workout_type = "None"
            else: workout_type = ', '.join(request.form.getlist('workoutType'))

        # Get unhealthy food info if user did not eat healthy
        if (ate_healthy != "Yes"):
            unhealthy_food = request.form.get('unhealthyFood')

        # Edge case handling
        if (len(proud_achievement) == 0): proud_achievement = "None"
        if (len(unhealthy_food) == 0): unhealthy_food = "None"

        # Creates and links stats to specific user
        user = User.query.filter_by(username=session["username"]).first()

        stats = Stats(overall_feeling=feeling,
                    time_slept=sleep,
                    worked_out=worked_out,
                    ate_healthy=ate_healthy,
                    time_worked_out=time_worked_out,
                    workout_type=workout_type,
                    unhealthy_food=unhealthy_food,
                    proud_achievement=proud_achievement,
                    owner=user)

        # If previous entry with same data exists, removes that entry
        date_today = str(datetime.today()).split()[0]

        for entry in user.stats:
            date_entry = str(entry.date_logged).split()[0]
            if date_today == date_entry:
                db.session.delete(entry)

        # Updates Changes to Database
        db.session.add(stats)
        db.session.commit()

        flash(f'Entry successfully added!', 'success')
        return redirect(url_for('stats'))

    return render_template("log_data.html")

@app.route("/search", methods=['GET', 'POST'])
def search():
    # If user is not logged in, redirect to home
    if "username" not in session:
        flash(f'You are not logged in!', 'danger')
        return redirect(url_for('home'))

    # Fires when submit button is pressed
    if request.method == 'POST':

        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()
        
        # If user doesn't exist, flash error
        if user is None:
            flash(f'Username does not exist', 'danger')
            return render_template("search.html")

        # Send table data of user to frontend
        table = list()
 
        for entry in user.stats:
            row = list()
            row.append(str(entry.date_logged).split()[0])
            row.append(entry.overall_feeling)
            row.append(entry.time_slept)
            row.append("Yes" if entry.worked_out else "No")
            row.append(entry.ate_healthy)
            row.append(entry.time_worked_out)
            row.append(entry.workout_type)
            row.append(entry.unhealthy_food)
            row.append(entry.proud_achievement)
            table.append(row)

        return render_template("search.html", table=table)

    return render_template("search.html")

@app.route("/register", methods=['GET', 'POST'])


def register():
    # If user is already logged in, redirect to home
    if "username" in session:
        flash(f'You are already logged in!', 'success')
        return redirect(url_for('home'))

   

    form = RegistrationForm()
    if form.validate_on_submit():

        # Get User Input from HTML Form
        username1 = request.form.get("username")
        email1 = request.form.get("email")
        password = request.form.get("password")

        
        #password checking function
        def password_check(passwd):
              
            SpecialSym =['$', '@', '#', '%', '~', '!', '^', '_', '+', '{', '}', '[', ']', ':', '<', '>', '.', ' ', '?', '/' ]
            blacklist = ['*', '=', '(', ')', '&', '|', ',', ';', '-', '\'', '"' ]
            val = True
     
            if len(passwd) < 6:
                alert = f"length should be at least 6"
                flash(alert)
                val = False
         
            if len(passwd) > 20:
                alert = f"length should be not be greater than 20"
                flash(alert)
                val = False
         
            if not any(char.isdigit() for char in passwd):
                alert = f"Password should has at least one numeral"
                flash(alert)
                print('Password should has at least one numeral')
                val = False
         
            if not any(char.isupper() for char in passwd):
                alert = f"Password should have at least one uppercase letter"
                flash(alert)
                print('Password should have at least one uppercase letter')
                val = False
         
            if not any(char.islower() for char in passwd):
                alert = f"Password should of at least one lowercase letter"
                flash(alert)
                print('Password should of at least one lowercase letter')
                val = False

            #sanitization
            if any(char in blacklist for char in passwd):
                alert = f"Password should not contain *  = ( ) & \" | , ; - ' symbols "
                flash(alert)
                print('Password should not contain blacklisted symbols')
                val = False
         
            if not any(char in SpecialSym for char in passwd):
                alert = f"Password should of at least one of teh symbols"
                flash(alert)
                print('Password should of at least one of teh symbols $@#')
                val = False
            if val:
                return val

        def register_check(reginput):
              
            black1 = ['*', '=', '(', ')', '&', '|', ',', ';', '-', '\'', '"' ]
            val = True

            if any(char in black1 for char in reginput):
                alert = f"Sorry, cannot accept your input! "
                flash(alert)
                print('Sorry, cannot accept your input!')
                val = False
            if val:
                return val

        #passing password
        if (password_check(password)):

        
            password = str(hashlib.sha3_256(password.encode()).hexdigest()) # Hash Password


            if (register_check(username1)):
                if(register_check(email1)):
                    #user = User(username=username, email=email, password=password)
                    user = User(username=username1, email=email1, password=password)
                    # Check to see username is already in use
                    if User.query.filter_by(username=username1).first() is not None:
                        flash(f'Registration Unsuccessful. The username you have entered is already in use', 'danger')
                        return render_template('register.html', title='Register', form=form)

                    # Check to see if email address is already in use
                    if User.query.filter_by(email=email1).first() is not None:
                        flash(f'Registration Unsuccessful. The email you have entered is already in use', 'danger')
                        return render_template('register.html', title='Register', form=form)

                    # Add user to database
                    db.session.add(user)
                    db.session.commit()

                # Create session for user
                    session.permanent = True
                    session["username"] = username1

                    flash(f'Registration Successful. Welcome, {username1}!', 'success')
                    return redirect(url_for('home'))
                else:
                    print('blacklisted email')
            else:
                print('blacklisted username')

        else:
            
            #alert = f"Your password should contain numbers, special characters, Upper case and lower case characters, and minimum length is 6"
            #flash(alert)
            print('password week')
            

            #for requirement in policy.test_password(password):
            #    alert = f"{requirement.name} not satisfied: expected: {requirement.requirement}, got: {requirement.actual}"
            #    flash(alert)
        

    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to home
    if "username" in session:
        flash(f'You are already logged in!', 'success')
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():

        #input sanitize
        def userinput_check(userinput):
              
            black = ['*', '=', '(', ')', '&', '|', ',', ';', '-', '\'', '"' ]
            val = True

            if any(char in black for char in userinput):
                alert = f"Sorry, cannot accept your input! "
                flash(alert)
                print('Sorry, cannot accept your input!')
                val = False
            if val:
                return val


        # Get User Input from HTML Form
        #email = request.form.get("email")
        useremail = request.form.get("email")

        pwdlogin = request.form.get("password")

        if (userinput_check(pwdlogin)):

            password = str(hashlib.sha3_256(pwdlogin.encode()).hexdigest()) # Sha3 - Hash Password

            if (userinput_check(useremail)):
                # Check if Login Credentials are correct
                #user = User.query.filter_by(email=email).first()
                user = User.query.filter_by(email=useremail).first()

                #if user is not None and email == user.email and password == user.password: 
                if user is not None and useremail == user.email and password == user.password: 
                    # Create session for user then redirect to home
                    session.permanent = True
                    session["username"] = user.username
                    flash(f'Welcome back, {user.username}!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Login Unsuccessful. Please check username and password', 'danger')

            else:
                print('blacklisted input-email')

        else:
            print('blacklisted input-password')

    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    # Removes user from session and redirects to home
    if "username" in session:
        flash(f'Welcome back, {session["username"]}!', 'success')
        session.pop("username", None)
    return redirect(url_for("home"))

if __name__ == '__main__':
    #app.run(debug=True)
    app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=("cert.pem", "key.pem"))
