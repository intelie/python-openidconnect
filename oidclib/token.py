# -*- coding: utf-8 -*-
from datetime import datetime
from datetime import timedelta
import jwt

from oauthlib.oauth2.rfc6749.tokens import BearerToken


class OIDCToken(BearerToken):
    def create_token(self, request, refresh_token=False):

        token = {
            'access_token': self.token_generator(request),
            'expires_in': self.expires_seconds(request),
            'token_type': 'Bearer',
            'id_token': self.create_id_token(request)
        }

        if request.scopes is not None:
            token['scope'] = ' '.join(request.scopes)

        if request.state is not None:
            token['state'] = request.state

        if refresh_token:
            if (request.refresh_token and
                    not self.request_validator.rotate_refresh_token(request)):
                token['refresh_token'] = request.refresh_token
            else:
                token['refresh_token'] = self.token_generator(
                        request, refresh_token=True)

        token.update(request.extra_credentials or {})

        self.request_validator.save_bearer_token(token, request)
        return token

    def create_id_token(self, request):
        payload = {
            'iss': self.request_validator.get_issuer(request.client_id, request),
            'sub': self.request_validator.get_subject(request.client_id, request),
            'aud': self.request_validator.get_audience(request.client_id, request),
            'iat': datetime.utcnow()
        }

        payload['exp'] = payload['iat'] + timedelta(seconds=self.expires_seconds(request))

        secret = self.request_validator.get_client_secret(request.client_id, request)
        return jwt.encode(payload, secret)

    def expires_seconds(self, request=None):
        if callable(self.expires_in):
            return self.expires_in(request)
        else:
            return self.expires_in
