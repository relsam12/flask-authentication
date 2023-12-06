from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# Configure Flask-login's login manager
login_manager = LoginManager()
login_manager.init_app(app)


# Create user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def is_authenticated(self):

        return True

    def is_active(self):
        True

    def is_anonymous(self):

        return False

    def get_id(self):
        return str(self.id)


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    # Passing True or False if the user is authenticated.
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        if user:
            # User already exist
            flash("You've already registered with that email. Please login or use other email!")
            return redirect(url_for('login'))

        # Hashing and salting the password entered by the user
        hash_and_salted_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256',
                                                          salt_length=8)
        new_user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        # return render_template("secrets.html", name=request.form.get("name"))
        return redirect('secrets')
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Find user by email entered.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        # Email doesn't exist or password incorrect.
        if not user:
            flash("that email doesn't exist, please try again or register first!")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Incorrect Password, please try again.")
            return redirect(url_for('login'))

        # Check stored password hash against entered password hashed.
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


# Only logged-in users can access the route
@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)

    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
