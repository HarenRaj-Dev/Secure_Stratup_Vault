from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField

class UploadFileForm(FlaskForm):
    file = FileField('Select File', validators=[FileRequired()])
    submit = SubmitField('Secure to Vault')