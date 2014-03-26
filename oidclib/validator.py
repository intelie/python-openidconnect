# -*- coding: utf-8 -*-
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

from oidclib import errors as oidc_errors


class OIDConnectValidator(RequestValidator):
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        This method does not need to be reimplemented. By default,
        all OIDC requests SHOULD have 'openid' on scope. So,
        if it doesn't have that, it's not an OIDC request.
        """
        if 'openid' not in scopes:
            raise oidc_errors.OpenIDScopeError(state=request.state, request=request)

        return True

    def save_authorization_code(self, *args, **kwargs):
        """Implementers of the OIDC Server must implement
        this method and check if 'openid' is one of the scopes,
        saving it accordingly to put the 'id_token' in
        the token request, later.
        """
        return super(OIDConnectValidator, self).save_authorization_code(*args, **kwargs)

    # for some of the methods below, please read:
    # http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    def get_client_secret(self, client_id, request):
        """
        The client_secret is the key used to sign the id_token,
        which is a Json Web Token (JWT). The client must use
        this same value to decode the token and check it.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_audience(self, client_id, request):
        """
        The audience(s) that the id_token is intended for. It has to
        return a list with at least one element, the client_id of
        the Relying Party.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_issuer(self, client_id, request):
        """
        The issuer is a case-sensitive URL representing the issuer
        of the response (the authentication provider)
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_subject(self, client_id, request):
        """
        A locally unique and never reassigned identifier for the end-user.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_code(self, *args, **kwargs):
        """
        Validates if the code given is valid and was issued in response
        to an OIDC request (you must save it on authorization step)
        """
        return super(OIDConnectValidator, self).validate_code(*args, **kwargs)

    def validate_nonce(self, client_id, nonce, client, request):
        """
        This method should return True or False if request.nonce is
        valid (never was used before). The implementer should ensure
        a nonce is never used twice.
        """
        raise NotImplementedError('Subclasses must implement this method.')
