from urllib.parse import urlparse, urljoin
from flask import request
import flask_wtf
import wtforms

from solid.db import User


# From https://web.archive.org/web/20120517003641/http://flask.pocoo.org/snippets/62/
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


class LoginForm(flask_wtf.FlaskForm):
    username = wtforms.StringField('Username')
    password = wtforms.PasswordField('Password')
    submit = wtforms.SubmitField('Submit')

    def __init__(self, *args, **kwargs):
        """Create instance."""
        super(LoginForm, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self, extra_validators=None):
        """Validate the form."""
        initial_validation = super(LoginForm, self).validate(extra_validators=extra_validators)
        if not initial_validation:
            print("FAIL INITIAL")
            print(self.errors)
            return False

        self.user = User.query.filter_by(user=self.username.data).first()
        if not self.user:
            self.username.errors.append('Unknown username')
            return False

        if not self.user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        if not self.user.is_active:
            self.username.errors.append('User not activated')
            return False
        return True
