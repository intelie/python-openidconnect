# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

from oidclib import errors as oidc_errors


class OIDConnectValidator(RequestValidator):
    # The following will be the default implementations
    #   - get_default_scopes
    #   - validate_client_id
    #   - get_default_redirect_uri
    #   - validate_redirect_uri

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        if 'openid' not in scopes:
            raise oidc_errors.OpenIDScopeError(state=request.state, request=request)

        return True

    def save_authorization_code(self, *args, **kwargs):
        """Implementers of the OIDC Server must implement
        this method and check if 'openid' is one of the scopes,
        saving it accordingly.
        """
        return super(OIDConnectValidator, self).save_authorization_code(*args, **kwargs)

    def get_client_secret(self, client_id, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_audience(self, client_id, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_issuer(self, client_id, request):
        raise NotImplementedError('Subclasses must implement this method.')

    def get_subject(self, client_id, request):
        raise NotImplementedError('Subclasses must implement this method.')
