"""
Custom Authenticator to use UltraAuth with JupyterHub

Derived using the Auth0, Github and Google OAuthenticator
implementations as examples.

The following environment variables may be used for configuration:

    AUTH0_SUBDOMAIN - The subdomain for your Auth0 account
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URL - Your callback handler URL

To prvent secrets being exposed by an env dump,
you can set the client_secret, client_id and
oauth_callback_url directly on the config for UltraAuthOAuthenticator.

One instance of this could be adding the following
to your jupyterhub_config.py :

  c.UltraAuthOAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.UltraAuthOAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.UltraAuthOAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.auth0.UltraAuthOAuthenticator' # NOQA

"""
import json

from os import environ

from tornado.auth import OAuth2Mixin
from tornado import gen

from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator
from .oauth2 import OAuthLoginHandler, OAuthenticator


class UltraAuthMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://srv.qryp.to/op/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://srv.qryp.to/op/oauth/token"

    _ULTRAAUTH_OPENID_ISSUER = environ.get('OPENID_ISSUER',
                                           'https://srv.qryp.to/op')
    _ULTRAAUTH_SCOPES_SUPPORTED = ['openid', 'email', 'profile', 'address']

    # TODO: get actual endpoints from django..we can't do discovery here


class UltraAuthLoginHandler(OAuthLoginHandler, UltraAuthMixin):
    pass


class UltraAuthAuthenticator(OAuthenticator):

    login_service = "UltraAuth"
    login_handler = UltraAuthLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.get_callback_url(handler)
        }

        # TODO: Change for UltraAuth
        url = "https://%s.auth0.com/oauth/token"

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/json"},
                          body=json.dumps(params)
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)}

        # TODO: Change for UltraAuth
        req = HTTPRequest("https://%s.auth0.com/userinfo",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return {
            'name': resp_json["email"],
            'auth_state': {
                'access_token': access_token,
                'auth0_user': resp_json,
            }
        }


class LocalAuth0OAuthenticator(LocalAuthenticator, UltraAuthAuthenticator):

    """A version that mixes in local system user creation"""
    pass
