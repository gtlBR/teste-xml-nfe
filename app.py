from flask import Flask, render_template, redirect, request, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import xml.etree.ElementTree as ET
import io
from datetime import datetime
import zipfile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave-secreta-chat'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # Limite de 1MB

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Modelo de usuário
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(413)
def too_large(e):
    flash('O tamanho total do upload não pode ultrapassar 1MB.', 'danger')
    return redirect(url_for('index'))

# Página inicial
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash('Usuário ou senha inválidos.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')

# Registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        confirm = request.form.get('confirm_password').strip()

        if not all([email, username, password, confirm]):
            flash('Todos os campos são obrigatórios.', 'danger')
            return redirect(url_for('register'))

        if password != confirm:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já cadastrado.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('E-mail já cadastrado.', 'danger')
            return redirect(url_for('register'))

        hashed = generate_password_hash(password)
        new_user = User(email=email, username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/esqueci')
def esqueci():
    return render_template('erro_fake.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Processamento de XML e ZIP
@app.route('/processar', methods=['POST'])
@login_required
def processar():
    arquivos = request.files.getlist('xml_files')
    ns = {'nfe': 'http://www.portalfiscal.inf.br/nfe'}
    linhas_excel = []

    for file in arquivos:
        nome = file.filename.lower()
        if nome.endswith('.zip'):
            try:
                with zipfile.ZipFile(file) as z:
                    for info in z.infolist():
                        if info.filename.lower().endswith('.xml'):
                            with z.open(info) as xmlfile:
                                processar_xml(xmlfile, linhas_excel, ns)
            except zipfile.BadZipFile:
                flash(f'Arquivo {nome} não é um ZIP válido.', 'danger')
        elif nome.endswith('.xml'):
            processar_xml(file, linhas_excel, ns)
        else:
            flash(f'Arquivo {nome} não é XML nem ZIP.', 'warning')

    if not linhas_excel:
        flash('Nenhum XML foi processado.', 'warning')
        return redirect(url_for('index'))

    df = pd.DataFrame(linhas_excel)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='NotasFiscais')
    output.seek(0)

    return send_file(output, download_name='relatorio_nfes.xlsx', as_attachment=True)

def processar_xml(file, linhas_excel, ns):
    tree = ET.parse(file)
    root = tree.getroot()
    infNFe = root.find('.//nfe:infNFe', ns)
    chave = infNFe.attrib.get('Id', '').replace('NFe', '') if infNFe is not None else ''

    ide = root.find('.//nfe:ide', ns)
    emit = root.find('.//nfe:emit', ns)
    dest = root.find('.//nfe:dest', ns)
    transp = root.find('.//nfe:transp', ns)
    cobr = root.find('.//nfe:cobr', ns)
    pag = root.find('.//nfe:pag', ns)
    infAdic = root.find('.//nfe:infAdic', ns)

    duplicatas = cobr.findall('.//nfe:dup', ns) if cobr is not None else []
    vencs = '; '.join([
        f"{d.findtext('nfe:dVenc', '', ns)} (R$ {d.findtext('nfe:vDup', '', ns)})"
        for d in duplicatas
    ])

    cab = {
        'Chave de Acesso': chave,
        'Número NF': ide.findtext('nfe:nNF', '', ns),
        'Data Emissão': formatar_data(ide.findtext('nfe:dhEmi', '', ns)),
        'Emitente': emit.findtext('nfe:xNome', '', ns),
        'Destinatário': dest.findtext('nfe:xNome', '', ns),
        'Transportadora': transp.findtext('nfe:transporta/nfe:xNome', '', ns) if transp is not None else '',
        'Tipo Frete': transp.findtext('nfe:modFrete', '', ns) if transp is not None else '',
        'Peso Bruto': transp.findtext('nfe:vol/nfe:pesoB', '', ns) if transp is not None else '',
        'Tipo Pagamento': pag.findtext('nfe:detPag/nfe:tPag', '', ns) if pag is not None else '',
        'Valor Pago': pag.findtext('nfe:detPag/nfe:vPag', '', ns) if pag is not None else '',
        'Vencimentos': vencs,
        'Informações Complementares': infAdic.findtext('nfe:infCpl', '', ns) if infAdic is not None else ''
    }

    for det in root.findall('.//nfe:det', ns):
        prod = det.find('nfe:prod', ns)
        imposto = det.find('nfe:imposto', ns)
        icms = imposto.find('.//nfe:ICMS00', ns) if imposto is not None else None
        ipi = imposto.find('.//nfe:IPITrib', ns) if imposto is not None else None
        pis = imposto.find('.//nfe:PISAliq', ns) if imposto is not None else None
        cofins = imposto.find('.//nfe:COFINSAliq', ns) if imposto is not None else None

        linha = cab.copy()
        linha.update({
            'Item': det.attrib.get('nItem', ''),
            'Produto': prod.findtext('nfe:xProd', '', ns),
            'Código Produto': prod.findtext('nfe:cProd', '', ns),
            'NCM': prod.findtext('nfe:NCM', '', ns),
            'CFOP': prod.findtext('nfe:CFOP', '', ns),
            'Quantidade': prod.findtext('nfe:qCom', '', ns),
            'Valor Unitário': prod.findtext('nfe:vUnCom', '', ns),
            'Valor Total': prod.findtext('nfe:vProd', '', ns),
            'ICMS (%)': icms.findtext('nfe:pICMS', '', ns) if icms is not None else '',
            'Valor ICMS': icms.findtext('nfe:vICMS', '', ns) if icms is not None else '',
            'IPI (%)': ipi.findtext('nfe:pIPI', '', ns) if ipi is not None else '',
            'Valor IPI': ipi.findtext('nfe:vIPI', '', ns) if ipi is not None else '',
            'Valor PIS': pis.findtext('nfe:vPIS', '', ns) if pis is not None else '',
            'Valor COFINS': cofins.findtext('nfe:vCOFINS', '', ns) if cofins is not None else '',
        })
        linhas_excel.append(linha)

def formatar_data(data_str):
    try:
        return datetime.fromisoformat(data_str).strftime('%d/%m/%Y')
    except:
        return data_str

if __name__ == '__main__':
    app.run(debug=True)
