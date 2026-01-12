from vault.models import Role, ActivityLog, Company, memberships
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
    
    # Check user's role in this company
    from sqlalchemy import select
    membership = db.session.execute(select(memberships).where(memberships.c.user_id == user.id, memberships.c.company_id == company_id)).first()
    if membership and membership[2]:  # role_id is not None
        role = Role.query.get(membership[2])
        if role and getattr(role, permission_attr, False):
            return True
    return False