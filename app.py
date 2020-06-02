import os
import secrets
from PIL import Image
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_dance.contrib.twitter import make_twitter_blueprint, twitter
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
app.config['SECRET_KEY'] = ')w1DN41!04gLw8{Y7/Zv$nY[h3$3%=3J?!^1@`}X6uS>kD6eN`UZo@2?&ns`NH'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
db.create_all()
bcrypt = Bcrypt(app)
loginM = LoginManager(app)
loginM.login_view = 'login'
loginM.login_message_category = 'info'
twitterBlueprint = make_twitter_blueprint(api_key='2ybCqYyhRTRt7kCj99fgSzKn0', api_secret='zDMDgzOeMnTEkkLgPw3Vi8OHozC7dw1oI0Wb8LQmGDrIf5i2FE')
githubBlueprint = make_github_blueprint(client_id='383c01177c9f9b2db36c', client_secret='e51f413a1888a85307005acaf251b999a928c73f')
googleBlueprint = make_google_blueprint(client_id='', client_secret='')
facebookBlueprint = make_facebook_blueprint(client_id='', client_secret='')
app.register_blueprint(twitterBlueprint, url_prefix='/login_twitter')
app.register_blueprint(githubBlueprint, url_prefix='/login_github')
app.register_blueprint(facebookBlueprint, url_prefix='/login_facebook')
app.register_blueprint(googleBlueprint, url_prefix='/login_google')

@loginM.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return 'Blog post ' + str(self.id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    imageFile = db.Column(db.String(20), nullable=False, default='default.jpg')

    def __repr__(self):
        return f"{self.username} with {self.email} and password {self.password}"

class LoginUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"{self.username} with {self.email}"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(140), nullable=False)
    author = db.Column(db.String(20), nullable=False)
    time = db.Column(db.DateTime(), default=datetime.utcnow)
    postID = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"{self.content} by {self.author} on {self.postID}"

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validateEmail(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(f"The email {email.data} is already being used for another account.")

    def validateUsername(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(f"The username {username.data} is already being used for another account.")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Login")

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField("Profile Picture", validators=[FileAllowed(["jpg", "jpeg", "png"])])
    submit = SubmitField('Update')

    def validateEmail(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(f"The email {email.data} is already being used for another account.")

    def validateUsername(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(f"The username {username.data} is already being used for another account.")

class AddComment(FlaskForm):
    body = StringField("Body", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Add Comment")

@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/posts', methods=['GET', 'POST'])
def posts():
        all_posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
        return render_template('posts.html', posts=all_posts)

@app.route("/comments/<int:post_id>", methods=["GET", "POST"])
def comments(post_id):
    post = BlogPost.query.get_or_404(post_id)
    all_comments = Comment.query.order_by(Comment.time.desc()).filter_by(postID=post_id)
    return render_template('comments.html', comments=all_comments, post=post)

@app.route('/posts/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    post = BlogPost.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    flash("Post has been deleted", "success")
    return redirect('/posts')

@app.route('/delete/account/<int:id>', methods=["GET", "POST"])
@login_required
def deleteAcc(id):
    account = User.query.get_or_404(id)
    comments = Comment.query.filter_by(postID=id)
    db.session.delete(account)
    db.session.delete(comments)
    db.session.commit()
    flash("Account has been deleted", "success")
    return redirect('/home')

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    
    post = BlogPost.query.get_or_404(id)

    if request.method == 'POST':
        post.title = request.form['title']
        post.author = request.form['author']
        post.content = request.form['content']
        db.session.commit()
        return redirect('/posts')
    else:
        return render_template('edit.html', post=post)

@app.route('/posts/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        post_title = request.form['title']
        post_author = request.form['author']
        post_content = request.form['content']
        new_post = BlogPost(title=post_title, content=post_content, author=post_author)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/posts')
        flash("Your post has been posted", "success")
    return render_template('new_post.html')

@app.route("/post/<int:id>")
def post(id):
    post = Post.query.get_or_404(id)
    return render_template('post.html', post=post)

@app.route("/comment/new/<int:post_id>", methods=["GET", "POST"])
@login_required
def newComment(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form['content']
        author = request.form['author']
        postID = request.form['id']
        comment = Comment(content=content, author=author, postID=postID)
        db.session.add(comment)
        db.session.commit()
        flash("Your comment has been added", "success")
        return redirect('/posts')
    return render_template('new_comment.html', post=post)

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        flash("You are logged in", "danger")
    form = RegistrationForm()
    if request.method == "POST":
        if form.validate_on_submit():
            Upassword = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            Uusername = form.username.data
            Uemail = form.email.data
            user = User(username=Uusername, email=Uemail, password=Upassword)
            db.session.add(user)
            db.session.commit()
            flash(f"Account created for {Uusername}. You can now log in!", "success")
            return redirect(url_for("login"))
    return render_template('register.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect('/home')
        flash("You are already logged in", "danger")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('account'))
            flash("You are now logged in", "success")
        else:
            flash("Login unsuccessful. Check email or password", "danger")
    return render_template('login.html', form=form)

def save_pic(form_picture):
    rHex = secrets.token_hex(8)
    _, fExt = os.path.splitext(form_picture.filename)
    pictureFn = rHex + fExt
    picPath = os.path.join(app.root_path, 'static/images', pictureFn)
    outSize = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(outSize)
    i.save(picPath)
    return pictureFn

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picFile = save_pic(form.picture.data)
            current_user.imageFile = picFile
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash("Your account has been updated", "success")
        return redirect(url_for('account'))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email
    imageFile = url_for('static', filename='images/' + current_user.imageFile)
    return render_template('account.html', imageFile=imageFile, form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect('/home')
    flash("You are now logged out", "success")

if __name__ == "__main__":
    app.run(debug=True)