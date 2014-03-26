# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import \
        AuthorizationCodeGrant as OAuthlibAuthorizationCodeGrant

from .base import GrantTypeMixin


class AuthorizationCodeGrant(GrantTypeMixin, OAuthlibAuthorizationCodeGrant):
    def validate_authorization_request(self, request):
        self.validate_scopes(request)

        self.validate_response_type(request, 'code')

        self.validate_client(request)

        self.validate_redirect_uri(request)

        return request.scopes, {
            'client_id': request.client_id,
            'redirect_uri': request.redirect_uri,
            'response_type': request.response_type,
            'state': request.state,
            'request': request
        }
