# app.py
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

# Загрузка переменных окружения
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Модель записи дневника
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    share_id = db.Column(db.String(36), unique=True, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('entries', lazy='dynamic'))

    def __repr__(self):
        return f'<Entry {self.date} {self.title}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Логин
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверные учётные данные')
    return render_template('login.html')

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Управление пользователями (только админ)
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Доступ запрещён')
        return redirect(url_for('index'))
    if request.method == 'POST':
        uname = request.form['username']
        email = request.form['email']
        pwd = request.form['password']
        if User.query.filter_by(username=uname).first():
            flash('Пользователь с таким именем уже существует')
        else:
            new_u = User(username=uname, email=email)
            new_u.set_password(pwd)
            db.session.add(new_u)
            db.session.commit()
            flash('Пользователь создан')
        return redirect(url_for('manage_users'))
    users = User.query.filter(User.username != current_user.username).all()
    return render_template('manage_users.html', users=users)

# Удаление пользователя
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Доступ запрещён')
        return redirect(url_for('index'))
    u = User.query.get_or_404(user_id)
    if u.is_admin:
        flash('Нельзя удалить админа')
    else:
        db.session.delete(u)
        db.session.commit()
        flash('Пользователь удалён')
    return redirect(url_for('manage_users'))

# Главная дневника
@app.route('/')
@login_required
def index():
    entries = Entry.query.filter_by(user_id=current_user.id).order_by(Entry.date.desc()).all()
    return render_template('index.html', entries=entries)

# Просмотр записи
@app.route('/entry/<int:entry_id>')
@login_required
def view_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id and not current_user.is_admin:
        flash('Доступ запрещён')
        return redirect(url_for('index'))
    return render_template('entry.html', entry=entry)

# Создание новой записи
@app.route('/new', methods=['GET', 'POST'])
@login_required
def new_entry():
    if request.method == 'POST':
        date_str = request.form['date']
        title = request.form['title']
        content = request.form['content']
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        share_id = str(uuid.uuid4())
        entry = Entry(date=date, title=title, content=content,
                      share_id=share_id, user_id=current_user.id)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_entry.html')

# Удаление записи
@app.route('/entry/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id and not current_user.is_admin:
        flash('Доступ запрещён')
        return redirect(url_for('index'))
    db.session.delete(entry)
    db.session.commit()
    flash('Запись удалена')
    return redirect(url_for('index'))


# Публичный просмотр по share_id
@app.route('/share/<share_id>')
def share_entry(share_id):
    entry = Entry.query.filter_by(share_id=share_id).first_or_404()
    return render_template('shared_entry.html', entry=entry)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Супер-админ из .env
        admin_un = os.getenv('ADMIN_USERNAME', 'admin')
        admin_pw = os.getenv('ADMIN_PASSWORD', 'adminpass')
        admin_em = os.getenv('ADMIN_EMAIL', 'admin@example.com')
        admin = User.query.filter_by(username=admin_un).first()
        if not admin:
            adm = User(username=admin_un, email=admin_em, is_admin=True)
            adm.set_password(admin_pw)
            db.session.add(adm)
        else:
            admin.email = admin_em
            admin.set_password(admin_pw)
        db.session.commit()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)