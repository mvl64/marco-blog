import os

from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from dotenv import load_dotenv  # pip install python-dotenv

from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

# load environment variables
# Remember these will be imported as strings, so any other type needs to be casty.
load_dotenv("D:/Development/EnvironmentVariables/.env")
secret_key = os.getenv("secret_key_blog")

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# configure application
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    # add a relationship to the BlogPost
    # the back_populates creates an "author" property in the BlogPost
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # define relationships:
    # create foreign key, which refers to the primary_key in table "users"
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    # create reference to the User object, "posts" will appear as a property in the User class
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # setup link to user table (foreign key)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    # add a property in the user table to access all comments by this user
    comment_author = relationship("User", back_populates="comments")

    # setup relation to BlogPost
    blog_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


# # define decorator for admins
def admin_only(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        is_admin = (current_user.is_authenticated and current_user.id == 1)
        if not is_admin:
            flash("This function is not accessible to you, please login as site administrator")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper_function


@app.route('/')
def get_all_posts():
    is_admin = (current_user.is_authenticated and current_user.id == 1)
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    user_form = RegisterForm()
    if user_form.validate_on_submit():
        name = user_form.name.data
        password = user_form.password.data
        email = user_form.email.data

        # check whether user already exists
        get_user = User.query.filter_by(email=email).first()
        if get_user:
            flash("You have already registered, please login instead")
            return redirect(url_for("login"))

        # hash password
        pw_hash = generate_password_hash(
            password=password,
            method="pbkdf2:sha256",
            salt_length=8
        )

        # store the user record
        new_user = User(
            name=name,
            email=email,
            password=pw_hash,
        )

        # save and commit
        db.session.add(new_user)
        db.session.commit()

        # login user, so they have access to more functions
        login_user(new_user)

        # return to home page
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=user_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # login and validate the user
        user_record = User.query.filter_by(email=form.email.data).first()
        if user_record:
            stored_hash = user_record.password
            user_pw = form.password.data
            if check_password_hash(stored_hash, user_pw):
                login_user(user_record)
                # flash("Logged in successfully.")

                # return to home page
                return redirect(url_for("get_all_posts"))

            flash("Invalid credentials supplied, please try again")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if not requested_post:
        return redirect(url_for("get_all_posts"))
    if form.validate_on_submit():
        # user has just submitted a comment
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.text.data,
                # author_id=current_user.id,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to be logged-in to comment")
            return redirect(url_for("login"))
    is_admin = (current_user.is_authenticated and current_user.id == 1)
    return render_template("post.html", form=form, post=requested_post,
                           logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if not post:
        # flash("Post number is invalid")
        return redirect(url_for("get_all_posts"))
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
