from oidclib import errors as oidc_errors


class Server(object):
    def __init__(self, oidcserver, oauthserver):
        self.oidc = oidcserver
        self.oauth = oauthserver

    def validate_authorization_request(self, *args, **kwargs):
        try:
            return self.oidc.validate_authorization_request(*args, **kwargs)
        except oidc_errors.OpenIDScopeError:
            return self.oauth.validate_authorization_request(*args, **kwargs)

    def validate_token_request(self, *args, **kwargs):
        try:
            return self.oidc.validate_token_request(*args, **kwargs)
        except oidc_errors.OIDCError:
            return self.oauth.validate_token_request(*args, **kwargs)
