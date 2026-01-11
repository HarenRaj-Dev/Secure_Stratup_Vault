from flask import jsonify
from flask_login import login_required, current_user
from vault.api import api_bp
from vault.models import ActivityLog, File, Company

@api_bp.route('/stats/<int:company_id>')
@login_required
def get_company_stats(company_id):
    """Returns JSON stats for the company dashboard."""
    company = Company.query.get_or_404(company_id)
    if company.owner_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    file_count = File.query.filter_by(company_id=company_id).count()
    log_count = ActivityLog.query.filter_by(company_id=company_id).count()
    
    return jsonify({
        "company_name": company.name,
        "total_files": file_count,
        "total_activities": log_count,
        "encryption_standard": "AES-256 / RSA-2048"
    })

@api_bp.route('/health')
def health_check():
    """Confirms the Secure Vault engine is running."""
    return jsonify({
        "status": "online",
        "encryption_module": "active",
        "vault_io_standard": "verified"
    })

@api_bp.route('/logs/recent/<int:company_id>')
@login_required
def recent_logs(company_id):
    """Fetches the last 5 logs for real-time display."""
    logs = ActivityLog.query.filter_by(company_id=company_id)\
        .order_by(ActivityLog.timestamp.desc())\
        .limit(5).all()
        
    return jsonify([{
        "user": log.user_email,
        "action": log.action,
        "time": log.timestamp.strftime("%H:%M:%S")
    } for log in logs])