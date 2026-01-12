from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, BooleanField
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
    perm_remove_user = BooleanField('Remove Users')
    perm_manage_roles = BooleanField('Manage Roles')
    perm_add_users = BooleanField('Add Users')
    submit = SubmitField('Save Role')

class AddUserForm(FlaskForm):
    email = StringField('User Email', validators=[DataRequired()])
    submit = SubmitField('Add User')