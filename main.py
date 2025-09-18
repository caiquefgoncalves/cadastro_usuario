from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
import fdb

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta'

bcrypt = Bcrypt(app)

host = 'localhost'
database = r'C:\Users\Aluno\Pictures\BANCO.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(host=host, database=database, user=user, password=password)


@app.route('/')
def index():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute('SELECT id_usuario, nome, email FROM usuarios ORDER BY nome')
        usuarios = cursor.fetchall()
        return render_template('usuarios.html', usuarios=usuarios, titulo='Lista de Usuarios')
    finally:
        cursor.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        cursor = con.cursor()
        try:

            cursor.execute('SELECT id_usuario, nome, senha FROM usuarios WHERE email = ?', (email,))
            usuario = cursor.fetchone()

            if usuario:
                if bcrypt.check_password_hash(usuario[2], senha):
                    session['usuario_id'] = usuario[0]
                    session['usuario_nome'] = usuario[1]
                    flash('Login realizado com sucesso!')
                    return redirect(url_for('index'))
                else:
                    flash('Email ou senha incorretos!')
            else:
                flash('Email ou senha incorretos!')
        finally:
            cursor.close()
    return render_template('login.html', titulo='Login')


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']

        if senha != confirmar_senha:
            flash('As senhas não coincidem!')
            return render_template('cadastro.html', titulo='Cadastro')

        senha_cripto = bcrypt.generate_password_hash(senha).decode('utf-8')

        cursor = con.cursor()
        try:
            cursor.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,))
            if cursor.fetchone():
                flash('Este email já está cadastrado!')
                return render_template('cadastro.html', titulo='Cadastro')

            cursor.execute('INSERT INTO usuarios (nome, email, senha) VALUES (?,?,?)', (nome, email, senha_cripto))
            con.commit()

            flash('Cadastro Realizado com Sucesso! Faça Login para Continuar')
            return redirect(url_for('login'))
        finally:
            cursor.close()

    return render_template('cadastro.html', titulo='Cadastro')


@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado')
    return redirect(url_for('login'))


@app.route('/novo')
def novo():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    return render_template('novo_usuario.html', titulo='Novo Usuario')


@app.route('/criar', methods=['POST'])
def criar():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    nome = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']
    confirmar_senha = request.form['confirmar_senha']


    if not nome or not email or not senha:
        flash('Todos os campos são obrigatórios!')
        return redirect(url_for('novo'))

    if senha != confirmar_senha:
        flash('As senhas não coincidem!')
        return redirect(url_for('novo'))

    if len(senha) < 8:
        flash('A senha deve ter no mínimo 8 caracteres!')
        return redirect(url_for('novo'))

    senha_cripto = bcrypt.generate_password_hash(senha).decode('utf-8')

    cursor = con.cursor()
    try:
        cursor.execute('SELECT 1 FROM usuarios WHERE email= ?', (email,))
        if cursor.fetchone():
            flash('Este email já está cadastrado!')
            return redirect(url_for('novo'))

        cursor.execute('INSERT INTO usuarios (nome, email, senha) VALUES(?,?,?)', (nome, email, senha_cripto))
        con.commit()

        flash('Usuario cadastrado com sucesso!')
        return redirect(url_for('index'))
    finally:
        cursor.close()


@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute('SELECT id_usuario, nome, email, senha FROM usuarios WHERE id_usuario = ?', (id,))
        usuario = cursor.fetchone()

        if not usuario:
            flash('Usuario não encontrado!')
            return redirect(url_for('index'))

        if request.method == 'POST':
            nome = request.form['nome']
            email = request.form['email']
            senha = request.form.get('senha', '')
            confirmar_senha = request.form.get('confirmar_senha', '')

            if not nome or not email:
                flash('Nome e Email são obrigatórios!')
                return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuario')

            if senha:
                if senha != confirmar_senha:
                    flash('As senhas não coincidem!')
                    return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuario')

                if len(senha) < 8:
                    flash('A senha deve ter no mínimo 8 caracteres')
                    return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuario')


                senha_cripto = bcrypt.generate_password_hash(senha).decode('utf-8')

            cursor.execute('SELECT 1 FROM usuarios WHERE email = ? AND id_usuario != ?', (email, id))
            if cursor.fetchone():
                flash('Este email já está em uso por outro usuário')
                return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuario')

            if senha:

                cursor.execute('UPDATE usuarios SET nome = ?, email = ?, senha = ? WHERE id_usuario = ?',
                               (nome, email, senha_cripto, id))
            else:
                cursor.execute('UPDATE usuarios SET nome = ?, email = ? WHERE id_usuario = ?', (nome, email, id))

            con.commit()
            flash('Usuario editado com sucesso!')
            return redirect(url_for('index'))

        return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuario')
    finally:
        cursor.close()


@app.route('/excluir/<int:id>', methods=['POST'])
def excluir(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()
    try:
        cursor.execute('SELECT 1 FROM usuarios WHERE id_usuario = ?', (id,))
        if not cursor.fetchone():
            flash('Usuario não encontrado!')
            return redirect(url_for('index'))

        cursor.execute('DELETE FROM usuarios WHERE id_usuario = ?', (id,))
        con.commit()

        flash('Usuario excluido com sucesso!')
        return redirect(url_for('index'))
    finally:
        cursor.close()


if __name__ == '__main__':
    app.run(debug=True)