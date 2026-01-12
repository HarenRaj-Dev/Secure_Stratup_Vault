from .extensions import db
from flask_login import UserMixin
from datetime import datetime
from vault.extensions import login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Junction table for User-Company Membership
memberships = db.Table('memberships',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('company_id', db.Integer, db.ForeignKey('company.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed
    rsa_private_key = db.Column(db.LargeBinary)  # Encrypted RSA Private Key
    rsa_public_key = db.Column(db.LargeBinary)   # RSA Public Key
    
    owned_companies = db.relationship('Company', backref='owner', lazy=True)
    files = db.relationship('File', backref='owner', lazy=True)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100)) # Company entry password
    logo = db.Column(db.String(100), default='logo.svg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    roles = db.relationship('Role', backref='company_ref', lazy=True)
    logs = db.relationship('ActivityLog', backref='company_ref', lazy=True)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'))
    
    # Permissions (Feature #7: Company role config page)
    perm_admin = db.Column(db.Boolean, default=False)
    perm_view = db.Column(db.Boolean, default=True)
    perm_modify = db.Column(db.Boolean, default=False)
    perm_upload = db.Column(db.Boolean, default=False)
    perm_download = db.Column(db.Boolean, default=False)
    perm_logs = db.Column(db.Boolean, default=False)
    perm_remove_user = db.Column(db.Boolean, default=False)
    perm_manage_roles = db.Column(db.Boolean, default=False)
    perm_add_users = db.Column(db.Boolean, default=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_name = db.Column(db.String(255), nullable=False) # Disk name
    encrypted_aes_key = db.Column(db.LargeBinary) # AES key encrypted with RSA
    iv = db.Column(db.LargeBinary) # AES Initialization Vector
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'))
    user_email = db.Column(db.String(150))
    action = db.Column(db.String(100)) # e.g., "Downloaded File: Q4_Report.pdf"
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)