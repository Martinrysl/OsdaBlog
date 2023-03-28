from flask import Flask, render_template, redirect, url_for, flash, request
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUser, Login
from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap
import werkzeug.security

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/martin/PycharmProjects/Last_Capstone/blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class NewUser(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return '<Email %r>' % self.email


@login_manager.user_loader
def load_user(user_id):
    return NewUser.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    form = RegisterUser()
    if form.validate_on_submit():
        name = form.user.data
        email = form.email.data
        password = form.password.data
        if NewUser.query.filter_by(email=email).first():
            flash(message="You have already signed up with that email", category="danger")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)

        new_user = NewUser(
            user=name,
            email=email,
            password=password_hash
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = db.session.query(NewUser).filter_by(email=email).first()
        if email == user.email and werkzeug.security.check_password_hash(pwhash=user.password, password=password):
            flash(message='Logged in successfully.')
            login_user(user)
            return redirect(url_for("get_all_posts"))
        elif email != user.email:
            error = 'Invalid email'
            flash(message="Invalid email!", category="danger")
            print('Wrong Email')
            render_template("login.html", form=form, error=error)
        elif werkzeug.security.check_password_hash(pwhash=user.password, password=password):
            error = 'Invalid password'
            flash(message="Invalid password!", category="danger")
            print('Wrong Password')
            render_template("login.html", form=form, error=error)

    return render_template("login.html", form=form, error=error)


@app.route('/logout')
def logout():
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post")
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
