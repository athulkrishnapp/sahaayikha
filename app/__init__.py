# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_mail import Mail  # Import Mail
from config import Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
mail = Mail()  # Initialize Mail

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)  # Initialize Mail with app

    # Flask-Login settings
    login_manager.login_view = 'main.user_login'
    login_manager.login_message_category = 'info'

    # Import and register blueprint
    from app.routes import main
    app.register_blueprint(main)

    # Create database tables and default settings
    with app.app_context():
        db.create_all()

        from app.models import SystemSetting
        if not SystemSetting.query.first():
            default_expiry = SystemSetting(key='ITEM_EXPIRY_DAYS', value='30')
            maintenance_mode = SystemSetting(key='MAINTENANCE_MODE', value='false')
            db.session.add(default_expiry)
            db.session.add(maintenance_mode)
            db.session.commit()

    return app