# -*- coding: utf-8 -*-
import mock
import jwt

from oidclib.token import OIDCToken

from .utils import BaseTest


class TestOIDCToken(BaseTest):
    def setup(self):
        self.request = self.make_request()

        self.SECRET = 'CLIENT SECRET'
        self.ISSUER = 'https://example.it/'
        self.SUBJECT = 'some random string'

        self.validator = mock.MagicMock()
        self.validator.get_client_secret.return_value = self.SECRET
        self.validator.get_issuer.return_value = self.ISSUER
        self.validator.get_subject.return_value = self.SUBJECT
        self.validator.get_audience.return_value = [self.request.client_id]

        self.token_generator = mock.Mock()
        self.token_generator.return_value = '1234567890'

        self.bearer = OIDCToken(self.validator, token_generator=self.token_generator)

    def test_create_bearer_token(self):
        request = self.make_request()
        token = self.bearer.create_token(request, refresh_token=True)

        expected_keys = ['access_token', 'id_token', 'refresh_token',
                'token_type', 'expires_in']

        self.assertHasKeys(token, expected_keys)
        self.validator.save_bearer_token.assert_called_with(token, request)

    def test_create_id_token(self):
        id_token = self.bearer.create_id_token(self.request)
        payload = jwt.decode(id_token, self.SECRET)
        
        self.validator.get_client_secret.assert_called_with(
                self.request.client_id, self.request)
        self.assertHasKeys(payload, ['iss', 'sub', 'aud', 'exp', 'iat'])

        self.validator.get_issuer.assert_called_with(
                self.request.client_id, self.request)
        assert payload['iss'] == self.ISSUER
        self.validator.get_subject.assert_called_with(
                self.request.client_id, self.request)
        assert payload['sub'] == self.SUBJECT
        self.validator.get_audience.assert_called_with(
                self.request.client_id, self.request)
        assert payload['aud'] == [self.request.client_id]

    def test_create_id_token_nonce(self):
        id_token = self.bearer.create_id_token(self.request, nonce='12345')
        payload = jwt.decode(id_token, self.SECRET)

        assert 'nonce' in payload
        assert payload['nonce'] == '12345'
