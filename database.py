from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Modelo de usuário com autenticação"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relacionamentos (se necessário)
    # documents = db.relationship('Document', backref='user', lazy=True)

    def set_password(self, password):
        """Gera hash da senha"""
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return f'<User {self.username}>'


class Document(db.Model):
    """Modelo para armazenar documentos XML processados"""
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    processed_data = db.Column(db.JSON)  # Armazena dados extraídos
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_processed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Document {self.filename}>'


def init_app(app):
    """Inicializa o banco de dados"""
    db.init_app(app)
    with app.app_context():
        db.create_all()