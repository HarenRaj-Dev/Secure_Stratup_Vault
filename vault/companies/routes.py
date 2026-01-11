from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from vault import db
from vault.models import Company, Role, ActivityLog, File
from vault.companies import companies_bp
from vault.companies.forms import CompanyForm, RoleForm
from vault.companies.services import log_activity, has_permission

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
    return render_template('companies/company_settings.html',form=form, title="New Company", company={'name': 'New Company'})

@companies_bp.route('/<int:company_id>/settings')
@login_required
def company_settings(company_id):
    company = Company.query.get_or_404(company_id)
    # Ensure only the owner can see settings
    if company.owner_id != current_user.id:
        flash("Only the owner can access settings.", "danger")
        return redirect(url_for('companies.company_files', company_id=company_id))
    return render_template('companies/company_settings.html', company=company)

@companies_bp.route('/<int:company_id>/files')
@login_required
def company_files(company_id):
    company = Company.query.get_or_404(company_id)
    if not has_permission(current_user, company_id, 'perm_view'):
        flash("Access Denied", "danger")
        return redirect(url_for('main.dashboard'))
    
    files = File.query.filter_by(company_id=company_id).all()
    log_activity(company_id, current_user.email, "Viewed company files")
    return render_template('companies/company_files.html', company=company, files=files)

@companies_bp.route('/<int:company_id>/roles', methods=['GET', 'POST'])
@login_required
def company_roles(company_id):
    company = Company.query.get_or_404(company_id)
    roles = Role.query.filter_by(company_id=company_id).all()
    return render_template('companies/company_roles.html', company=company, roles=roles)

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
    return render_template('companies/role_config.html', company=company, form=form)

@companies_bp.route('/<int:company_id>/logs')
@login_required
def company_logs(company_id):
    company = Company.query.get_or_404(company_id)
    logs = ActivityLog.query.filter_by(company_id=company_id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template('companies/company_logs.html', company=company, logs=logs)

@companies_bp.route('/<int:company_id>/users')
@login_required
def company_users(company_id):
    company = Company.query.get_or_404(company_id)
    # This fetches all users associated with the company (memberships)
    # For now, we render the template to stop the BuildError
    return render_template('companies/company_users.html', company=company)