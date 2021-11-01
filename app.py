from flask import Flask,flash, g, redirect, render_template, request, session, url_for,jsonify
from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost/lo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "random string"


db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=True, nullable=False)


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))

        return view(**kwargs)

    return wrapped_view


# @app.route('/welcome')
# def welcome():
#     return jsonify({'message':'Welcome user'})


@app.route('/')
def index():
    return render_template('base.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif Users.query.filter_by(username=username,password=password).first() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            u = Users(username=username, password=password)
            db.session.add(u)
            db.session.commit()
            # error = 'You have successfully registered. Now you can login'
            return redirect(url_for('login'))

        flash(error)

    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        user = Users.query.filter_by(username=username).first()
        pswd = Users.query.filter_by(password=password).first()

        if user is None:
            error = 'Incorrect username.'
        elif pswd is None:
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user.id
            # session['user_id'] = Users.query.get('id')
            # return redirect(url_for('index'))
            return redirect(url_for('welcome'))

        flash(error)

    return render_template('login.html')


@app.route('/welcome')
def welcome():
    # Check if user is loggedin
    if 'user_id' in session:
        return render_template('home.html')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
    # session.clear()
    session.pop('user_id', None)
    return redirect(url_for('login'))


# @app.before_app_request
# def load_logged_in_user():
#     user_id = session.get('user_id')
#
#     if user_id is None:
#         g.user = None
#     else:
#         # g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
#         g.user = Users.query.get(user_id)
#
#
# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    print("table created")
    app.run(debug=True)