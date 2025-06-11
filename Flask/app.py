from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "senha123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pets.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"

# Criar pasta de uploads se não existir
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nome_completo = db.Column(db.String(100), nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamento com pets
    pets_para_adocao = db.relationship('Pet', foreign_keys='Pet.owner_id', backref='dono', lazy='dynamic')
    pets_adotados = db.relationship('Pet', foreign_keys='Pet.adotado_por_id', backref='adotante', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Pet(db.Model):
    pet_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tipo_pet = db.Column(db.String(10), nullable=False)
    nome_pet = db.Column(db.String(30), nullable=False)
    raca_pet = db.Column(db.String(15), nullable=False)
    idade_pet = db.Column(db.Integer, nullable=False)
    personalidade_pet = db.Column(db.String(300), nullable=False)
    foto_pet = db.Column(db.String(100), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    disponivel = db.Column(db.Boolean, default=True)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    adotado_por_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    data_adocao = db.Column(db.DateTime, nullable=True)

class LoginForm(FlaskForm):
    username = StringField("Nome de Usuário", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Entrar")

class RegisterForm(FlaskForm):
    username = StringField("Nome de Usuário", validators=[DataRequired(), Length(min=4, max=20)])
    nome_completo = StringField("Nome Completo", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField("Confirmar Senha", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Criar Conta")

class PetForm(FlaskForm):
    tipo_pet = StringField("Você quer colocar um cachorro, um gato ou um coelho para adoção?", validators=[DataRequired()])
    nome_pet = StringField("Qual é o nome do pet?", validators=[DataRequired()])
    raca_pet = StringField("Qual a raça do pet?", validators=[DataRequired()])
    idade_pet = StringField("Qual a idade do pet?", validators=[DataRequired()])
    personalidade_pet = StringField("Fale um pouco sobre a personalidade do pet", validators=[DataRequired()])
    foto_pet = FileField("Adicione uma foto do pet", validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Apenas imagens são permitidas!')])
    solicitar = SubmitField("solicitar")

with app.app_context():
    db.create_all()

def get_current_user():
    """Função para obter o usuário atual da sessão"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def require_auth():
    """Verifica se o usuário está autenticado"""
    return 'user_id' in session

@app.route('/')
def home():
    user = get_current_user()
    return render_template("home.html", user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if require_auth():
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Nome de usuário ou senha incorretos.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if require_auth():
        return redirect(url_for('home'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Verificar se o usuário já existe
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Nome de usuário já existe. Escolha outro.', 'error')
            return render_template('register.html', form=form)
        
        # Criar novo usuário
        user = User(
            username=form.username.data,
            nome_completo=form.nome_completo.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso!', 'info')
    return redirect(url_for('home'))

@app.route('/pets-disponiveis')
def pets_disponiveis():
    if not require_auth():
        flash('Você precisa estar logado para ver os pets disponíveis.', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    try:
        # Buscar pets disponíveis que não são do usuário atual
        pets = Pet.query.filter(Pet.disponivel == True, Pet.owner_id != user.id).all()
    except Exception as e:
        print("houve um erro", e)
        flash('Erro ao carregar pets. Recriando banco de dados...', 'error')
        db.drop_all()
        db.create_all()
        pets = []
    
    return render_template("pets_disponiveis.html", template_pets=pets, user=user)

@app.route('/meus-pets')
def meus_pets():
    if not require_auth():
        flash('Você precisa estar logado para ver seus pets.', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    try:
        pets = Pet.query.filter_by(owner_id=user.id).all()
    except Exception as e:
        print("houve um erro", e)
        flash('Erro ao carregar seus pets.', 'error')
        pets = []
    
    return render_template("meus_pets.html", template_pets=pets, user=user)

@app.route('/solicitacao', methods = ["GET", "POST"])
def solicitacao():
    if not require_auth():
        flash('Você precisa estar logado para adicionar um pet.', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    formulario = PetForm()
    if formulario.validate_on_submit():
        # Processar upload da foto
        foto_filename = None
        if formulario.foto_pet.data:
            foto = formulario.foto_pet.data
            foto_filename = secure_filename(foto.filename)
            # Adicionar timestamp para evitar conflitos de nome
            import time
            foto_filename = f"{int(time.time())}_{foto_filename}"
            foto.save(os.path.join(app.config["UPLOAD_FOLDER"], foto_filename))
        
        novo_pet = Pet(
            tipo_pet = formulario.tipo_pet.data.lower(),
            nome_pet = formulario.nome_pet.data,
            raca_pet = formulario.raca_pet.data,
            idade_pet = int(formulario.idade_pet.data),
            personalidade_pet = formulario.personalidade_pet.data,
            foto_pet = foto_filename,
            owner_id = user.id
        )
        db.session.add(novo_pet)
        db.session.commit()
        flash('Pet adicionado com sucesso!', 'success')
        return redirect(url_for("meus_pets"))

    return render_template("solicitacao.html", template_form=formulario, user=user)

@app.route('/adotar/<int:pet_id>')
def adotar_pet(pet_id):
    if not require_auth():
        flash('Você precisa estar logado para adotar um pet.', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    pet = Pet.query.get_or_404(pet_id)
    
    if pet.owner_id == user.id:
        flash('Você não pode adotar seu próprio pet!', 'error')
        return redirect(url_for('pets_disponiveis'))
    
    if not pet.disponivel:
        flash('Este pet já foi adotado!', 'error')
        return redirect(url_for('pets_disponiveis'))
    
    # Realizar a adoção
    pet.disponivel = False
    pet.adotado_por_id = user.id
    pet.data_adocao = datetime.utcnow()
    
    db.session.commit()
    flash(f'Parabéns! Você adotou {pet.nome_pet}!', 'success')
    return redirect(url_for('pets_disponiveis'))

@app.route('/pets-adotados')
def pets_adotados():
    if not require_auth():
        flash('Você precisa estar logado para ver seus pets adotados.', 'warning')
        return redirect(url_for('login'))
    
    user = get_current_user()
    try:
        pets = Pet.query.filter_by(adotado_por_id=user.id).all()
    except Exception as e:
        print("houve um erro", e)
        flash('Erro ao carregar pets adotados.', 'error')
        pets = []
    
    return render_template("pets_adotados.html", template_pets=pets, user=user)

@app.route('/reset-database')
def reset_database():
    """Rota para resetar completamente o banco de dados"""
    try:
        # Limpar todas as tabelas
        db.drop_all()
        # Recriar as tabelas
        db.create_all()
        flash('Banco de dados resetado com sucesso! Todos os dados foram removidos.', 'success')
    except Exception as e:
        flash(f'Erro ao resetar banco de dados: {str(e)}', 'error')
    
    # Limpar a sessão atual
    session.clear()
    return redirect(url_for('home'))