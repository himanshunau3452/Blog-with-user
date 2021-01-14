from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, Login, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import ForeignKey

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
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

login_manager = LoginManager()
login_manager.init_app(app)



##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_comment = relationship('Comments', back_populates='blog')


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comment = relationship('Comments', back_populates='user')


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    user = relationship('User', back_populates='comment')
    blog = relationship('BlogPost', back_populates='user_comment')


db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def admin_only(func):
        @wraps(func)
        def wrap(*args, **kwargs):
            if current_user.is_authenticated:
                print(current_user.is_authenticated)
                if current_user.id == 1:
                    return func(*args, **kwargs)
                else:
                    return abort(403)
            else:
                return abort(403)

        return wrap


@app.route('/')
@login_required
def get_all_posts():
    posts = BlogPost.query.all()
    # print(current_user.id)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
        user = User(name=form.name.data, password=password, email=form.email.data)
        try:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        except:
            flash("The email address already exist.")
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.username.data
        user = User.query.filter_by(email=email).first()
        if user:
            password = form.password.data
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password is incorrect")
        else:
            flash(f"No user found with the email address {email}")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        comment = Comments(
            comment=form.comment.data,
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(comment)
        db.session.commit()

    comments = db.session.query(Comments).filter_by(post_id=post_id).all()
    author = User.query.all()
    return render_template("post.html", post=requested_post, form=form, comments=comments, authors=author)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            author_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@login_manager.unauthorized_handler
def unauthorized_handler():
    flash("Unautherized access, please first login and then try to access the page.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
