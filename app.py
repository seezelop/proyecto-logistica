from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

# Crear la aplicación Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta'  # Cambia esto por una clave segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(20), nullable=False)  # 'tecnico' o 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Ruta inicial
@app.route('/')
def index():
    return "Bienvenido al sistema de logística"

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and usuario.check_password(password):
            login_user(usuario)
            return redirect(url_for('index'))
        else:
            return "Email o contraseña incorrectos"

    return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Ruta para el panel de administrador
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.rol != 'admin':
        return "Acceso denegado", 403

    usuarios = Usuario.query.all()
    return render_template('admin_panel.html', usuarios=usuarios)

# Ruta para consultar usuarios
@app.route('/consultar_usuarios')
def consultar_usuarios():
    with app.app_context():
        usuarios = Usuario.query.all()
        if usuarios:
            print("La base de datos contiene usuarios:")
            for usuario in usuarios:
                print(f"ID: {usuario.id}, Nombre: {usuario.nombre}, Email: {usuario.email}, Rol: {usuario.rol}")
        else:
            print("La base de datos está vacía.")
    
    return "Consulta de usuarios completada. Revisa la consola para ver los resultados."


# Crear un usuario administrador inicial
def create_admin():
    with app.app_context():
        # Verificar si el usuario administrador ya existe
        admin = Usuario.query.filter_by(email="admin@example.com").first()
        
        if not admin:
            # Crear el usuario administrador si no existe
            admin = Usuario(nombre="Admin", email="admin@example.com", rol="admin")
            admin.set_password("contraseña_segura")  # Cambia esto por una contraseña segura
            db.session.add(admin)
            db.session.commit()

# Ejecutar la aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crear la base de datos si no existe
        create_admin()   # Crear el usuario administrador inicial

    app.run(debug=True)