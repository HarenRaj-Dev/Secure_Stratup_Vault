from flask import render_template, redirect, url_for, flash, current_app, send_file
from flask_login import login_required, current_user
from vault import db
from vault.models import Company, Role, ActivityLog, File, User, memberships
from vault.companies import companies_bp
from vault.companies.forms import CompanyForm, RoleForm, AddUserForm
from vault.main.forms import UploadFileForm
from vault.crypto_utils import encrypt_file_data, decrypt_file_data
from vault.companies.services import log_activity, has_permission
from werkzeug.utils import secure_filename
from flask_wtf.csrf import generate_csrf
import os
import uuid
import io

def get_user_companies():
    """Helper function to get all companies the current user has access to"""
    from sqlalchemy import select
    owned_companies = Company.query.filter_by(owner_id=current_user.id).all()
    member_companies_query = db.session.execute(
        select(Company).join(memberships, Company.id == memberships.c.company_id).where(memberships.c.user_id == current_user.id)
    ).all()
    member_companies = [row[0] for row in member_companies_query]
    return list(set(owned_companies + member_companies))

@companies_bp.route('/new', methods=['GET', 'POST'])
@login_required
def create_company():
    form = CompanyForm()
    if form.validate_on_submit():
        new_company = Company(
            name=form.name.data,
            password=form.password.data,
            owner_id=current_user.id
        )
        db.session.add(new_company)
        db.session.commit()
        
        # Create a default Admin role for the company
        admin_role = Role(name="Administrator", company_id=new_company.id, perm_admin=True)
        db.session.add(admin_role)
        db.session.commit()
        
        flash(f'Company {new_company.name} created successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    # Pass a dictionary representing a new company to avoid the 'Undefined' error
    return render_template('companies/company_settings.html',form=form, company={'name': 'New Company'}, csrf_token=generate_csrf(), companies=get_user_companies())

@companies_bp.route('/<int:company_id>/settings', methods=['GET', 'POST'])
@login_required
def company_settings(company_id):
    company = Company.query.get_or_404(company_id)
    # Ensure only the owner can see settings
    if company.owner_id != current_user.id:
        flash("Only the owner can access settings.", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    form = CompanyForm()
    form.name.data = company.name
    form.password.data = company.password
    if form.validate_on_submit():
        company.name = form.name.data
        company.password = form.password.data
        if form.logo.data:
            logo_file = form.logo.data
            logo_filename = secure_filename(logo_file.filename)
            logo_path = os.path.join(current_app.root_path, 'static', 'img', logo_filename)
            logo_file.save(logo_path)
            company.logo = logo_filename
        db.session.commit()
        flash("Company settings updated!", "success")
        return redirect(url_for('companies.company_settings', company_id=company_id))
    
    return render_template('companies/company_settings.html', company=company, form=form, csrf_token=generate_csrf(), companies=get_user_companies())

@companies_bp.route('/<int:company_id>/delete', methods=['POST'])
@login_required
def delete_company(company_id):
    company = Company.query.get_or_404(company_id)
    if company.owner_id != current_user.id:
        flash("Only the owner can delete the company.", "danger")
        return redirect(url_for('companies.company_settings', company_id=company_id))
    
    # Delete associated files, roles, logs, etc.
    File.query.filter_by(company_id=company_id).delete()
    Role.query.filter_by(company_id=company_id).delete()
    ActivityLog.query.filter_by(company_id=company_id).delete()
    db.session.delete(company)
    db.session.commit()
    flash("Company deleted successfully.", "success")
    return redirect(url_for('main.dashboard'))

@companies_bp.route('/<int:company_id>/files')
@login_required
def company_files(company_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_view'):
        flash("Access Denied", "danger")
        return redirect(url_for('main.dashboard'))
    
    files = File.query.filter_by(company_id=company_id).all()
    
    # Calculate file sizes
    for file in files:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.encrypted_name)
        if os.path.exists(file_path):
            file.size = os.path.getsize(file_path)
        else:
            file.size = 0
    
    log_activity(company_id, current_user.email, "Viewed company files")
    form = UploadFileForm()
    return render_template('companies/company_files.html', company=company, files=files, form=form, companies=get_user_companies())

@companies_bp.route('/<int:company_id>/upload', methods=['POST'])
@login_required
def upload_company_file(company_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_upload'):
        flash("Access Denied", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    form = UploadFileForm()
    if form.validate_on_submit():
        file_storage = form.file.data
        original_filename = file_storage.filename
        
        # Encrypt
        file_content = file_storage.read()
        encrypted_data, encrypted_aes_key, iv = encrypt_file_data(file_content, current_user.rsa_public_key)
        
        # Save
        unique_name = str(uuid.uuid4())
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # DB
        new_file = File(
            filename=original_filename,
            encrypted_name=unique_name,
            user_id=current_user.id,
            company_id=company_id,
            encrypted_aes_key=encrypted_aes_key,
            iv=iv
        )
        db.session.add(new_file)
        db.session.commit()
        
        log_activity(company_id, current_user.email, f"Uploaded file: {original_filename}")
        flash(f'File {original_filename} uploaded to company!', 'success')
    return redirect(url_for('companies.company_files', company_id=company_id))

@companies_bp.route('/<int:company_id>/download/<int:file_id>')
@login_required
def download_company_file(company_id, file_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_download'):
        flash("Access Denied", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    file_record = File.query.get_or_404(file_id)
    if file_record.company_id != company_id:
        flash("File not found in this company.", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    # Read encrypted file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_record.encrypted_name)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt
    decrypted_data = decrypt_file_data(
        encrypted_data, 
        file_record.encrypted_aes_key, 
        file_record.iv, 
        current_user.rsa_private_key
    )
    
    log_activity(company_id, current_user.email, f"Downloaded file: {file_record.filename}")
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_record.filename,
        as_attachment=True
    )

@companies_bp.route('/<int:company_id>/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_company_file(company_id, file_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_modify'):
        flash("Access Denied", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    file_to_delete = File.query.get_or_404(file_id)
    if file_to_delete.company_id != company_id:
        flash("File not found in this company.", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    
    db.session.delete(file_to_delete)
    db.session.commit()
    log_activity(company_id, current_user.email, f"Deleted file: {file_to_delete.filename}")
    flash("File removed from company vault.", "success")
    return redirect(url_for('companies.company_files', company_id=company_id))

@companies_bp.route('/<int:company_id>/roles', methods=['GET', 'POST'])
@login_required
def company_roles(company_id):
    company = Company.query.get_or_404(company_id)
    roles = Role.query.filter_by(company_id=company_id).all()
    return render_template('companies/company_roles.html', company=company, roles=roles, companies=get_user_companies())

@companies_bp.route('/<int:company_id>/roles/config', methods=['GET', 'POST'])
@login_required
def role_config(company_id):
    company = Company.query.get_or_404(company_id)
    form = RoleForm()
    if form.validate_on_submit():
        new_role = Role(
            name=form.name.data,
            company_id=company_id,
            perm_admin=form.perm_admin.data,
            perm_view=form.perm_view.data,
            perm_modify=form.perm_modify.data,
            perm_upload=form.perm_upload.data,
            perm_download=form.perm_download.data,
            perm_logs=form.perm_logs.data
        )
        db.session.add(new_role)
        db.session.commit()
        flash("Role updated!", "success")
        return redirect(url_for('companies.company_roles', company_id=company_id))
    return render_template('companies/role_config.html', company=company, form=form, companies=get_user_companies())

@companies_bp.route('/<int:company_id>/logs')
@login_required
def company_logs(company_id):
    company = Company.query.get_or_404(company_id)
    logs = ActivityLog.query.filter_by(company_id=company_id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template('companies/company_logs.html', company=company, logs=logs, companies=get_user_companies())

@companies_bp.route('/<int:company_id>/users')
@login_required
def company_users(company_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_view'):
        flash("Access Denied", "danger")
        return redirect(url_for('main.dashboard'))
    
    # Fetch members
    from sqlalchemy import select
    members_query = db.session.execute(
        select(User, Role)
        .join(memberships, User.id == memberships.c.user_id)
        .join(Role, memberships.c.role_id == Role.id)
        .where(memberships.c.company_id == company_id)
    ).all()
    
    members = []
    for user, role in members_query:
        members.append({
            'user': user,
            'role': role,
            'is_owner': user.id == company.owner_id
        })
    
    return render_template('companies/company_users.html', company=company, members=members, companies=get_user_companies())

@companies_bp.route('/<int:company_id>/add_user', methods=['GET', 'POST'])
@login_required
def add_company_user(company_id):
    company = Company.query.get_or_404(company_id)
    if company.owner_id != current_user.id:
        flash("Only the owner can add users.", "danger")
        return redirect(url_for('companies.company_users', company_id=company_id))
    
    form = AddUserForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('companies.add_company_user', company_id=company_id))
        
        # Check if already in company
        from sqlalchemy import select
        existing = db.session.execute(select(memberships).where(memberships.c.user_id == user.id, memberships.c.company_id == company_id)).first()
        if existing:
            flash("User already in company.", "danger")
            return redirect(url_for('companies.company_users', company_id=company_id))
        
        # Get default role
        default_role = Role.query.filter_by(company_id=company_id).first()
        if not default_role:
            flash("No roles available. Create a role first.", "danger")
            return redirect(url_for('companies.company_roles', company_id=company_id))
        
        # Add to memberships
        from sqlalchemy import insert
        db.session.execute(insert(memberships).values(user_id=user.id, company_id=company_id, role_id=default_role.id))
        db.session.commit()
        
        log_activity(company_id, current_user.email, f"Added user: {email}")
        flash("User added to company.", "success")
        return redirect(url_for('companies.company_users', company_id=company_id))
    
    return render_template('companies/add_user.html', company=company, form=form, companies=get_user_companies())