from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email, Length, ValidationError
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterUser(FlaskForm):
    user = StringField('Username', validators=[DataRequired()])
    email = EmailField(label='Email', validators=[DataRequired(), Email(granular_message=True,
                                                                        check_deliverability=True)])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     Length(max=50, min=8,
                                                            message='Password must have at least 8 characters')])
    submit = SubmitField('Submit')


class Login(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')
