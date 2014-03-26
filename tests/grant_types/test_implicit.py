# -*- coding: utf-8 -*-
import mock
import pytest
from urlparse import urlparse, parse_qs
from oauthlib.oauth2.rfc6749 import errors

from oidclib.token import OIDCToken
from oidclib.grant_types import ImplicitGrant
from oidclib import errors as oidc_errors

from ..utils import BaseTest


class TestImplicitGrant(BaseTest):
    def setup(self):
        self.validator = mock.MagicMock()
        self.grant = ImplicitGrant(request_validator=self.validator)

    def test_validate_authorization_request_invalid_response_type(self):
        request = self.make_request()

        with pytest.raises(errors.UnsupportedGrantTypeError):
            self.grant.validate_authorization_request(request)

    def test_validate_authorization_request_missing_nonce(self):
        request = self.make_request(response_type='id_token')

        with pytest.raises(oidc_errors.MissingNonceError):
            self.grant.validate_authorization_request(request)

    def test_validate_authorization_request_invalid_nonce(self):
        request = self.make_request(response_type='id_token', nonce='invalid')
        self.validator.validate_nonce.side_effect = oidc_errors.InvalidNonceError()

        with pytest.raises(oidc_errors.InvalidNonceError):
            self.grant.validate_authorization_request(request)
        self.validator.validate_nonce.assert_called_with(
            request.client_id, 'invalid', request.client, request)

    def test_validate_authorization_request_missing_redirect_uri(self):
        request = self.make_request(response_type='id_token', nonce='some nonce',
                redirect_uri=None)
        self.validator.get_default_redirect_uri.return_value = ''

        with pytest.raises(errors.MissingRedirectURIError):
            self.grant.validate_authorization_request(request)

    def test_create_token_response(self):
        request = self.make_request(response_type='id_token', nonce='some nonce',
                scopes=['openid', 'profile'])
        token_handler = OIDCToken(self.validator)
        self.validator.get_subject.return_value = 'subject'
        self.validator.get_issuer.return_value = 'issuer'
        self.validator.get_audience.return_value = [request.client_id]
        self.validator.get_client_secret.return_value = 'secret'

        headers, body, status = self.grant.create_token_response(request, token_handler)
        url = urlparse(headers['Location'])
        fragments = parse_qs(url.fragment)
        self.assertHasKeys(fragments, ['id_token', 'expires_in', 'scope'])
