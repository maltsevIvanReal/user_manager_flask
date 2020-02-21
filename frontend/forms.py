from flask_wtf import FlaskForm
from wtforms import StringField, HiddenField, SelectField
from wtforms.validators import DataRequired


class MyFormAdd(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])


class MyFormDelete(FlaskForm):
    user_id = HiddenField("user_id", validators=[DataRequired()])
    group_id = HiddenField("group_id", validators=[DataRequired()])
    id = HiddenField("id", validators=[DataRequired()])
    readonly = StringField("readonly", render_kw={'readonly': True})


class MyFormUpdate(FlaskForm):
    oldname = HiddenField("oldname", validators=[DataRequired()])
    newname = StringField("newname", validators=[DataRequired()])


class MyFormSelectRoleUser(FlaskForm):
    role_id = SelectField("role_id")
    user_id = HiddenField("user_id", validators=[DataRequired()])


class MyFormSelectGroupUser(FlaskForm):
    id = SelectField("group_id")
    user_id = HiddenField("user_id", validators=[DataRequired()])


class MyFormSelectGroupRole(FlaskForm):
    group_id = SelectField("group_id")
    role_id = HiddenField("role_id", validators=[DataRequired()])


class LoginForm(FlaskForm):
    Login = SelectField("login")
