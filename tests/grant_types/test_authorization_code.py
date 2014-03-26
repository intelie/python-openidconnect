# -*- coding: utf-8 -*-
import mock
import pytest
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors

from oidclib.grant_types import AuthorizationCodeGrant
from oidclib import errors as oidc_errors

from ..utils import BaseTest


class TestAuthorizationCodeGrant(BaseTest):
    def setup(self):
        self.validator = mock.MagicMock()
        self.validator.get_default_scopes.return_value = 'read write'
        self.auth = AuthorizationCodeGrant(request_validator=self.validator)

    def test_request_missing_openid_scope(self):
        self.validator.validate_scopes.side_effect = oidc_errors.OpenIDScopeError()
        request = Request('https://a.b/path')

        with pytest.raises(oidc_errors.OpenIDScopeError):
            self.auth.validate_authorization_request(request)

    def test_request_invalid_client_id(self):
        request = Request('https://a.b./path')
        request.scope = 'openid profile'
        request.response_type = 'code'
        with pytest.raises(errors.MissingClientIdError):
            self.auth.validate_authorization_request(request)

        request.client_id = 'invalid_client'
        self.validator.validate_client_id.return_value = False
        with pytest.raises(errors.InvalidClientIdError):
            self.auth.validate_authorization_request(request)

    def test_validate_authorization_request_required_parameters(self):
        """
        Tests the expected validation of required parameters,
        acording to 3.1.2.1 spec
        """

        request = self.make_request()
        scopes, credentials = self.auth.validate_authorization_request(request)

        self.assertListEqual(scopes, request.scope.split())
        assert credentials['client_id'] == request.client_id
        assert credentials['redirect_uri'] == request.redirect_uri
        assert credentials['response_type'] == request.response_type
        assert credentials['state'] == request.state

        self.validator.validate_client_id\
                .assert_called_once_with(request.client_id, request)
        self.validator.validate_redirect_uri\
                .assert_called_once_with(request.client_id, request.redirect_uri, request)

    def test_validate_token_request_unsupported_grant_type(self):
        request = self.make_request()

        with pytest.raises(errors.UnsupportedGrantTypeError):
            self.auth.validate_token_request(request)

    def test_validate_token_request_missing_code(self):
        request = self.make_request(grant_type='authorization_code')

        with pytest.raises(errors.InvalidRequestError):
            self.auth.validate_token_request(request)

    def test_validate_token_request_valid(self):
        request = self.make_request(grant_type='authorization_code', code='12345')
        self.validator.validate_grant_type.return_value = True
        self.validator.validate_code.return_value = True
        self.validator.client_authentication_required.return_value = True
        self.validator.authenticate_client.side_effect = self._authenticate

        self.auth.validate_token_request(request)
        self.validator.validate_grant_type.assert_called_with(
                request.client_id, request.grant_type, request.client, request)

    def _authenticate(self, request):
        request.user = mock.MagicMock()
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked_client_id'
        return True
