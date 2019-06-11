
# A very simple Flask Hello World app for you to get started with...

from flask import Flask , render_template,url_for,redirect,flash,request,jsonify,g,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user,LoginManager,UserMixin,login_required,logout_user,current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField,TextAreaField
from wtforms.validators import DataRequired,Length,Email,EqualTo,ValidationError
from datetime import datetime
from flask_moment import Moment
from flask_socketio import SocketIO






app = Flask(__name__)

#设置数据库
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="liujian",
    password="wanghui123321",
    hostname="liujian.mysql.pythonanywhere-services.com",
    databasename="liujian$comments",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["DEBUG"]=True
app.secret_key = "something only you know"


login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
moment = Moment(app)
socketio = SocketIO(app)




# set Comment.model
class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    content = db.Column(db.String(4096))
    timestamp = db.Column(db.DateTime,default=datetime.utcnow,index=True)



#set User.model by flask-login.UserMixin
class User(db.Model,UserMixin):
    """User db_model"""
    __tablename__='User'
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),unique=True)
    email = db.Column(db.String(50),unique=True)
    password_hash = db.Column(db.String(128))

    # 验证密码
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

# set forms#######################
# a login form
class LoginForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(),Length(1,20)])
    password = PasswordField('Password',validators=[DataRequired(),Length(1,128)])
    #remember = BooleanField('Remember me')
    submit = SubmitField('Log in')


class RegistrationForm(FlaskForm):
    username = StringField('Username：',validators=[DataRequired(),Length(1,20)])
    email = StringField('Email：',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired(), Length(1,128)])
    password2 = PasswordField(
        'Repeat Password：',validators = [DataRequired(),Length(1,128),EqualTo('password')])
    submit = SubmitField('Register')


    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if  user is not None:
            raise ValidationError('Please use a different username')
    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email .')

class CommentForm(FlaskForm):
    content = TextAreaField('content',validators=[DataRequired(),Length(1,200)])
    submit = SubmitField('say something')

#load User
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/nothing", methods=["GET", "POST"])
def nothing():
    flash('Congratulations,you are now a registered user!')
    return 'nothing in here'

@app.route("/", methods=["GET", "POST"])
def index():
    comments = Comment.query.order_by(Comment.timestamp.desc()).all()
    form = CommentForm()
    if form.validate_on_submit():
        content = form.content.data
        comment = Comment(content=content,name=current_user.username)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('main_page.html',form=form,comments=comments)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    #handel the POST

    if form.validate_on_submit():
         user = User.query.filter_by(username=form.username.data).first()

         if user is None or not user.check_password(form.password.data):
             return render_template('login.html',error=True,form=form)
         #after validate user , login the user
         else:
            login_user(user)
            return redirect(url_for('index'))

    # handel the GET
    return render_template('login.html',form=form,error=False)


@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
    #if request.method=="POST":
        user = User(username=form.username.data,email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations,you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)



@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#include lyq
@app.route("/lyq")
def lyq():
    return render_template("lyq.html")

@app.route("/login2/", methods=["GET", "POST"])
def login2():
    if current_user.is_authenticated:
        return redirect(url_for('lyq'))
    form = LoginForm()
    #handel the POST

    if form.validate_on_submit():
         user = User.query.filter_by(username=form.username.data).first()

         if user is None or not user.check_password(form.password.data):
             return render_template('login.html',error=True,form=form)
         #after validate user , login the user
         else:
            login_user(user)
            return redirect(url_for('lyq'))

    # handel the GET
    return render_template('login.html',form=form,error=False)

@app.route("/logout2/")
@login_required
def logout2():
    logout_user()
    return redirect(url_for('lyq'))


global_user = []

@app.route('/card')
def card():
    return render_template('card.html')

@app.route('/start',methods=["GET","POST"])
def start():
    if request.method=="POST":
        global global_user
        user = request.form.get('data')
        if user not in global_user:
            g.user = global_user
            global_user.append(user)

        data = {'data':len(g.user)}
        return jsonify(data)

