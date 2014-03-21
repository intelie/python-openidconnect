# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import \
        AuthorizationCodeGrant as OAuthlibAuthorizationCodeGrant
from oauthlib.uri_validate import is_absolute_uri


class AuthorizationCodeGrant(OAuthlibAuthorizationCodeGrant):
    def validate_authorization_request(self, request):
        # TODO there's still a lot of work to do,
        # TODO see oauth2.rfc6749.grant_types.authorization_code.AuthorizationCodeGrant#validate_authorization_request

        # REQUIRED, validating 'openid' in scope and response_type=code
        self.validate_scopes(request)

        if request.response_type != 'code':
            raise errors.UnsupportedGrantTypeError(state=request.state, request=request)

        # REQUIRED, validating client_id
        if not request.client_id:
            raise errors.MissingClientIdError(state=request.state, request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(state=request.state, request=request)

        # REQUIRED, validating redirect_uri
        if not request.redirect_uri:
            request.redirect_uri = self.request_validator.get_default_redirect_uri(
                    request.client_id, request)

            if not request.redirect_uri:
                raise errors.MissingRedirectURIError(state=request.state, request=request)

        if not is_absolute_uri(request.redirect_uri):
            raise errors.InvalidRedirectURIError(state=request.state, request=request)

        if not self.request_validator.validate_redirect_uri(request.client_id,
                request.redirect_uri, request):
            raise errors.MismatchingRedirectURIError(state=request.state, request=request)

        return request.scopes, {
            'client_id': request.client_id,
            'redirect_uri': request.redirect_uri,
            'response_type': request.response_type,
            'state': request.state,
            'request': request
        }
