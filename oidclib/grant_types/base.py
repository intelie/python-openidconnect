from oauthlib.uri_validate import is_absolute_uri
from oauthlib.oauth2.rfc6749 import errors


class GrantTypeMixin(object):
    def validate_response_type(self, request, *response_types):
        req_response_type = set(request.response_type.split())

        for response_type in response_types:
            if req_response_type == set(response_type.split()):
                return

        raise errors.UnsupportedGrantTypeError(state=request.state, request=request)

    def validate_redirect_uri(self, request):
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

    def validate_client(self, request):
        if not request.client_id:
            raise errors.MissingClientIdError(state=request.state, request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(state=request.state, request=request)
