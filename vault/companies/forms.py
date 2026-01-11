from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, FileField
from wtforms.validators import DataRequired, Length

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Company Password', validators=[DataRequired()])
    logo = FileField('Company Logo')
    submit = SubmitField('Create Company')

class RoleForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired()])
    perm_admin = BooleanField('Administrator')
    perm_view = BooleanField('View Files')
    perm_modify = BooleanField('Modify Files')
    perm_upload = BooleanField('Upload Files')
    perm_download = BooleanField('Download Files')
    perm_logs = BooleanField('View Activity Logs')
    submit = SubmitField('Save Role')