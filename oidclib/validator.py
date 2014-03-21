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

    def get_default_redirect_uri(self, client_id, request):
        pass
