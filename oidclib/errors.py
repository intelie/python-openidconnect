# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749.errors import Oauth2Error


class OpenIDScopeError(OAuth2Error):
    error = 'missing_openid_scope'
    description = ('Authorization request is not a valid OpenID Connect request '
                   'due to the lack of the "openid" scope')
