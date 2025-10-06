from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Инициализация приложения
app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db = SQLAlchemy(app)

# Инициализация менеджера авторизации
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему'

# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' или 'recruiter'
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_person = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship('User', backref=db.backref('clients', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршруты
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'recruiters_count': User.query.filter_by(role='recruiter').count(),
        'clients_count': Client.query.count(),
        'my_clients_count': Client.query.filter_by(created_by=current_user.id).count() if current_user.role == 'recruiter' else 0
    }
    return render_template('dashboard.html', stats=stats)

# Рекрутеры (только для админа)
@app.route('/recruiters')
@login_required
def recruiters():
    if current_user.role != 'admin':
        flash('У вас нет доступа к этой странице', 'error')
        return redirect(url_for('dashboard'))
    
    recruiters_list = User.query.filter_by(role='recruiter').all()
    return render_template('recruiters.html', recruiters=recruiters_list)

@app.route('/add_recruiter', methods=['POST'])
@login_required
def add_recruiter():
    if current_user.role != 'admin':
        flash('Доступ запрещен', 'error')
        return redirect(url_for('recruiters'))
    
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('Пользователь с таким логином уже существует', 'error')
        return redirect(url_for('recruiters'))
    
    recruiter = User(
        username=username,
        full_name=full_name,
        phone=phone,
        role='recruiter'
    )
    recruiter.set_password(password)
    
    db.session.add(recruiter)
    db.session.commit()
    
    flash('Рекрутер успешно добавлен', 'success')
    return redirect(url_for('recruiters'))

@app.route('/edit_recruiter/<int:id>', methods=['POST'])
@login_required
def edit_recruiter(id):
    if current_user.role != 'admin':
        flash('Доступ запрещен', 'error')
        return redirect(url_for('recruiters'))
    
    recruiter = User.query.get_or_404(id)
    if recruiter.role != 'recruiter':
        flash('Пользователь не является рекрутером', 'error')
        return redirect(url_for('recruiters'))
    
    recruiter.full_name = request.form.get('full_name')
    recruiter.phone = request.form.get('phone')
    recruiter.username = request.form.get('username')
    
    new_password = request.form.get('password')
    if new_password:
        recruiter.set_password(new_password)
    
    db.session.commit()
    
    flash('Данные рекрутера обновлены', 'success')
    return redirect(url_for('recruiters'))

@app.route('/delete_recruiter/<int:id>')
@login_required
def delete_recruiter(id):
    if current_user.role != 'admin':
        flash('Доступ запрещен', 'error')
        return redirect(url_for('recruiters'))
    
    recruiter = User.query.get_or_404(id)
    if recruiter.role != 'recruiter':
        flash('Пользователь не является рекрутером', 'error')
        return redirect(url_for('recruiters'))
    
    # Проверяем, есть ли у рекрутера клиенты
    if Client.query.filter_by(created_by=recruiter.id).first():
        flash('Невозможно удалить рекрутера, у которого есть клиенты', 'error')
        return redirect(url_for('recruiters'))
    
    db.session.delete(recruiter)
    db.session.commit()
    
    flash('Рекрутер удален', 'success')
    return redirect(url_for('recruiters'))

# Клиенты (доступны всем авторизованным пользователям)
@app.route('/clients')
@login_required
def clients():
    if current_user.role == 'admin':
        clients_list = Client.query.all()
    else:
        clients_list = Client.query.filter_by(created_by=current_user.id).all()
    
    return render_template('clients.html', clients=clients_list)

@app.route('/add_client', methods=['POST'])
@login_required
def add_client():
    name = request.form.get('name')
    contact_person = request.form.get('contact_person')
    phone = request.form.get('phone')
    
    client = Client(
        name=name,
        contact_person=contact_person,
        phone=phone,
        created_by=current_user.id
    )
    
    db.session.add(client)
    db.session.commit()
    
    flash('Клиент успешно добавлен', 'success')
    return redirect(url_for('clients'))

@app.route('/edit_client/<int:id>', methods=['POST'])
@login_required
def edit_client(id):
    client = Client.query.get_or_404(id)
    
    # Проверяем права доступа
    if current_user.role != 'admin' and client.created_by != current_user.id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('clients'))
    
    client.name = request.form.get('name')
    client.contact_person = request.form.get('contact_person')
    client.phone = request.form.get('phone')
    
    db.session.commit()
    
    flash('Данные клиента обновлены', 'success')
    return redirect(url_for('clients'))

@app.route('/delete_client/<int:id>')
@login_required
def delete_client(id):
    client = Client.query.get_or_404(id)
    
    # Проверяем права доступа
    if current_user.role != 'admin' and client.created_by != current_user.id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('clients'))
    
    db.session.delete(client)
    db.session.commit()
    
    flash('Клиент удален', 'success')
    return redirect(url_for('clients'))

# Смена пароля
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Текущий пароль неверен', 'error')
        elif new_password != confirm_password:
            flash('Новые пароли не совпадают', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# Инициализация базы данных
def init_db():
    with app.app_context():
        db.create_all()
        
        # Создаем администратора по умолчанию, если его нет
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                full_name='Администратор',
                phone='-',
                role='admin'
            )
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print('✅ Создан администратор: admin/admin')

if __name__ == '__main__':
    init_db()
    print('🚀 Сервер запускается...')
    print('📊 Откройте: http://localhost:5000')
    print('🔐 Логин: admin / admin')
    app.run(debug=True, host='0.0.0.0', port=5000)