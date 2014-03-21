# -*- coding: utf-8 -*-
import mock
import pytest
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors

from oidclib.grant_types import AuthorizationCodeGrant
from oidclib.validator import OIDConnectValidator
from oidclib import errors as oidc_errors


class TestAuthorizationCodeGrant(object):
    def setup(self):
        self.validator = OIDConnectValidator()
        self.validator.validate_client_id = mock.Mock()
        self.validator.validate_redirect_uri = mock.Mock()
        self.validator.get_default_scopes = mock.Mock()
        self.validator.get_default_scopes.return_value = 'read write'
        self.auth = AuthorizationCodeGrant(request_validator=self.validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = 'mocked'
        return True

    def make_request(self, response_type='code',
            scope='openid profile email'):
        request = Request('https://a.b/path')

        request.scope = scope
        request.client = 'superman'
        request.client_id = 'abcdef'
        request.redirect_uri = 'https://a.b/'
        request.response_type = response_type

        return request

    def assertListEqual(self, list1, list2):
        return sorted(list1) == sorted(list2)

    def test_request_missing_openid_scope(self):
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

