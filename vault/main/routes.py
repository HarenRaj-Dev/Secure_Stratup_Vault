import os
import uuid
import io
from flask import render_template, url_for, flash, redirect, request, current_app, send_file
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf
from vault import db
# CHANGE: Import the blueprint from the local __init__.py file
from vault.extensions import main_bp 
from vault.main.forms import UploadFileForm
from vault.models import File, Company, memberships
from vault.crypto_utils import decrypt_file_data
from vault.crypto_utils import encrypt_file_data, decrypt_file_data

# REMOVE the line: main_bp = Blueprint("main", __name__) 
# (It is now created in __init__.py)

@main_bp.route("/")
@main_bp.route("/dashboard")
@login_required
def dashboard():
    # ... rest of your code remains the same ...
    # Fetch user's personal files (where company_id is NULL)
    user_files = File.query.filter_by(user_id=current_user.id, company_id=None).all()
    
    # Calculate file sizes
    for file in user_files:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.encrypted_name)
        if os.path.exists(file_path):
            file.size = os.path.getsize(file_path)
        else:
            file.size = 0
    
    # Fetch companies for the sidebar list (owned or member)
    from sqlalchemy import select
    owned_companies = Company.query.filter_by(owner_id=current_user.id).all()
    member_companies_query = db.session.execute(
        select(Company).join(memberships, Company.id == memberships.c.company_id).where(memberships.c.user_id == current_user.id)
    ).all()
    member_companies = [row[0] for row in member_companies_query]
    user_companies = list(set(owned_companies + member_companies))
    form = UploadFileForm()
    return render_template('main/dashboard.html', 
                           files=user_files, 
                           companies=user_companies, 
                           form=form,
                           company=None,
                           csrf_token=generate_csrf())

@main_bp.route("/upload", methods=['POST'])
@login_required
def upload_file():
    form = UploadFileForm()
    if form.validate_on_submit():
        file_storage = form.file.data
        original_filename = file_storage.filename
        
        # 1. Read file and Encrypt
        file_content = file_storage.read()
        encrypted_data, aes_key, iv = encrypt_file_data(file_content, current_user.rsa_public_key)
        
        # 2. Save encrypted blob to disk
        unique_name = str(uuid.uuid4())
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # 3. Save metadata to DB
        new_file = File(
            filename=original_filename,
            encrypted_name=unique_name,
            encrypted_aes_key=aes_key,
            iv=iv,
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash(f'File "{original_filename}" has been encrypted and secured!', 'success')
    return redirect(url_for('main.dashboard'))

@main_bp.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Check ownership
    if file_record.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.dashboard'))
    
    # 1. Read encrypted file from disk
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_name)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # 2. Decrypt using User's Private Key
    decrypted_data = decrypt_file_data(
        encrypted_data, 
        file_record.encrypted_aes_key, 
        file_record.iv, 
        current_user.rsa_private_key
    )
    
    # 3. Send back to user
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_record.filename,
        as_attachment=True
    )

@main_bp.route('/file/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_to_delete = File.query.get_or_404(file_id)
    if file_to_delete.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.dashboard'))
    
    db.session.delete(file_to_delete)
    db.session.commit()
    flash("File removed from vault.", "success")
    return redirect(url_for('main.dashboard'))

@main_bp.route("/view/<int:file_id>")
@login_required
def view_file(file_id):
    file_record = File.query.get_or_404(file_id)
    
    # Check ownership
    if file_record.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.dashboard'))
    
    # 1. Read encrypted file from disk
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_name)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # 2. Decrypt using User's Private Key
    decrypted_data = decrypt_file_data(
        encrypted_data, 
        file_record.encrypted_aes_key, 
        file_record.iv, 
        current_user.rsa_private_key
    )
    
    # 3. Send back to user for viewing
    return send_file(
        io.BytesIO(decrypted_data),
        mimetype='application/pdf',  # Or detect type based on extension
        as_attachment=False
    )