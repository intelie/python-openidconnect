# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749.errors import OAuth2Error


class OIDCError(OAuth2Error):
    pass


class OpenIDScopeError(OIDCError):
    error = 'missing_openid_scope'
    description = ('Authorization request is not a valid OpenID Connect request '
                   'due to the lack of the "openid" scope')


class NotOpenIDConnectError(OIDCError):
    error = 'not_oidc_request'
