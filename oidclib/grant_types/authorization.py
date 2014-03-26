# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import \
        AuthorizationCodeGrant as OAuthlibAuthorizationCodeGrant

from .base import GrantTypeMixin


class AuthorizationCodeGrant(GrantTypeMixin, OAuthlibAuthorizationCodeGrant):
    def validate_authorization_request(self, request):
        # TODO there's still a lot of work to do,
        # TODO see oauth2.rfc6749.grant_types.authorization_code.AuthorizationCodeGrant#validate_authorization_request

        # REQUIRED, validating 'openid' in scope and response_type=code
        self.validate_scopes(request)

        self.validate_response_type(request, 'code')

        # REQUIRED, validating client_id
        self.validate_client(request)

        self.validate_redirect_uri(request)

        return request.scopes, {
            'client_id': request.client_id,
            'redirect_uri': request.redirect_uri,
            'response_type': request.response_type,
            'state': request.state,
            'request': request
        }
