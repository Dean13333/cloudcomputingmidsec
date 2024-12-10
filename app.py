from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate  # 引入 Flask-Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup
from flask_mailman import Mail, message



app = Flask(__name__)  # 定義 Flask 應用
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = 'your_salt'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'


mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)  # 定義 SQLAlchemy 資料庫
migrate = Migrate(app, db)  # 初始化 Flask-Migrate

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 最愛功能的關聯表
favorites = db.Table('favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'))
)

# 使用者模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    bio = db.Column(db.Text, nullable=True)  # 用戶簡介
    favorites = db.relationship('Post', secondary=favorites, backref='favorited_by')

# 文章模型
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))

# 評論模型
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='comments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 註冊表單
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# 登入表單
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField('Login')

# 重設密碼表單
class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=50)])
    submit = SubmitField('Request Password Reset')

class NewPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=4, max=20)])
    confirm_password = PasswordField('Confirm New Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# 初始化資料庫
with app.app_context():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password, email=form.username.data)  # 加上 email
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    get_flashed_messages()  # 清除之前的 Flash 訊息

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return '''
                <script>
                    alert('登入失敗，請檢查帳號或密碼。');
                    window.location.href = "/login";
                </script>
            '''
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出')
    return redirect(url_for('index'))

@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

@app.route('/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_post = Post(title=title, content=content, author_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_post.html')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    
    if request.method == 'POST':
        comment_content = request.form['comment']
        if comment_content:
            new_comment = Comment(content=comment_content, post_id=post.id, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully.', 'success')
        else:
            flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('show_post', post_id=post.id))
    
    return render_template('show_post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/favorite', methods=['POST'])
@login_required
def favorite_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post in current_user.favorites:
        current_user.favorites.remove(post)
        db.session.commit()
        flash('已從最愛中移除文章')
    else:
        current_user.favorites.append(post)
        db.session.commit()
        flash('文章已新增至最愛')
    return redirect(url_for('show_post', post_id=post.id))

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author_id != current_user.id:
        flash("You cannot edit someone else's post!")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))
    
    return render_template('edit_post.html', post=post)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author_id != current_user.id:
        flash("You cannot delete someone else's post!")
        return redirect(url_for('index'))
    
    db.session.delete(post)
    db.session.commit()
    flash('Post has been deleted', 'success')
    return redirect(url_for('index'))

@app.route('/myaccount')
@login_required
def my_account():
    my_posts = Post.query.filter_by(author_id=current_user.id).all()
    my_favorites = current_user.favorites
    return render_template('my_account.html', my_posts=my_posts, my_favorites=my_favorites)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.email = request.form['email']
        current_user.bio = request.form['bio']
        current_user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256') if request.form['password'] else current_user.password
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
            msg.body = f'To reset your password, visit the following link: {reset_url}'
            mail.send(msg)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found', 'danger')
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('The reset link is invalid or has expired', 'danger')
        return redirect(url_for('reset_password_request'))
    form = NewPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    posts = Post.query.filter(Post.title.contains(query) | Post.content.contains(query)).all() if query else []
    return render_template('search_results.html', posts=posts)

if __name__ == '__main__':
    app.run(debug=True)