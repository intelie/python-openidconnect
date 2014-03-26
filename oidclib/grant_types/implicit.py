# -*- coding: utf-8 -*-
from oauthlib import common
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import ImplicitGrant as OAuthlibImplicitGrant

from .base import GrantTypeMixin
from oidclib import errors as oidc_errors


class ImplicitGrant(GrantTypeMixin, OAuthlibImplicitGrant):
    def create_token_response(self, request, token_handler):
        try:
            if not request.scopes:
                raise ValueError('Scopes must be set on post auth.')

            self.validate_token_request(request)
        except errors.FatalClientError as e:
            # log
            raise
        except errors.OAuth2Error as e:
            # log
            return {
                'Location': common.add_params_to_uri(request.redirect_uri,
                    e.twotuples, fragment=True)
            }, None, 302

        token = token_handler.create_token(request, refresh_token=False)
        return {
            'Location': common.add_params_to_uri(request.redirect_uri,
                token.items(), fragment=True)
        }, None, 302

    def validate_token_request(self, request):
        # REQUIRED, client needs to be authenticated
        self.validate_client(request)

        # REQUIRED, 'openid' should be listed
        self.validate_scopes(request)

        # REQUIRED, response_type should be either 'id_token token' or 'id_token'
        self.validate_response_type(request, 'id_token', 'id_token token')

        # REQUIRED, nonce should be passed on request
        self.validate_nonce(request)

        # REQUIRED, redirect_uri must be set
        self.validate_redirect_uri(request)

        return request.scopes, {
            'client_id': request.client_id,
            'redirect_uri': request.redirect_uri,
            'response_type': request.response_type,
            'state': request.state,
            'nonce': request.nonce,
            'request': request
        }

    def validate_nonce(self, request):
        if not request.nonce:
            raise oidc_errors.MissingNonceError(state=request.state, request=request)

        if not self.request_validator.validate_nonce(request.client_id, request.nonce,
                request.client, request):
            raise oidc_errors.InvalidNonceError(state=request.state, request=request)
