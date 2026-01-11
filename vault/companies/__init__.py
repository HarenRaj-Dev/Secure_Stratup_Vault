from flask import Blueprint

companies_bp = Blueprint('companies', __name__, url_prefix='/companies')

from . import routes