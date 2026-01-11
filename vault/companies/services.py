from vault.models import Role, ActivityLog, Company
from vault import db
from flask import request

def log_activity(company_id, user_email, action):
    new_log = ActivityLog(
        company_id=company_id,
        user_email=user_email,
        action=action,
        ip_address=request.remote_addr
    )
    db.session.add(new_log)
    db.session.commit()

def has_permission(user, company_id, permission_attr):
    # Owners always have full permission
    company = Company.query.get(company_id)
    if company.owner_id == user.id:
        return True
    
    # Check roles assigned to this user in this company (logic for memberships)
    # Simplified for your college project structure:
    role = Role.query.filter_by(company_id=company_id).first() # In a full app, map user to role
    if role and getattr(role, permission_attr):
        return True
    return False