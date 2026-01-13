from flask import Flask
# Step 1: Add main_bp to this import line
from .extensions import db, login_manager, main_bp 

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration from instance/config.py
    app.config.from_pyfile('../instance/config.py', silent=True)
    
    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    with app.app_context():
        # Register Blueprints
        from .auth.routes import auth_bp
        from .companies.routes import companies_bp
        
        # Step 2: Import the routes for 'main' so the @main_bp.route decorators run
        from .main import routes 

        app.register_blueprint(auth_bp)
        # Step 3: Register the main_bp that we imported from extensions at the top
        app.register_blueprint(main_bp) 
        app.register_blueprint(companies_bp)

        # Create database tables for our models
        from . import models
        db.create_all()

    import os
    # Create uploads folder if it doesn't exist
    # Use abspath to ensure Python finds the folder outside the vault directory
    upload_path = os.path.abspath(os.path.join(app.root_path, '..', 'uploads'))
    if not os.path.exists(upload_path):
        os.makedirs(upload_path)

    return app