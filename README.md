OIDClib (WIP)
=============

An implementation of [OpenID Connect][1] for Python, on top of [OAuthlib][2].


IMPLEMENTATION DETAILS
----------------------

*Oidclib* defines a new server, `OpenIDConnectServer`, which replaces 
oauthlib's pre-configured server. Note that this server **can only** handle
OIDC requests, i.e., it will fail with regular OAuth2 requests. A full-featured
server is on the planning, though.

The current implementation tries to reuse all four basic endpoints defined
in `oauthlib.oauth2.rfc6749.endpoints`, just creating a new server and
new grant\_types for the three OIDC workflows. Due to the unique requirements
of OpenID Connect, a validator with some new methods is required.


oidclib.grant\_types.authorization.AuthorizationCodeGrant
--------------------------------------------------------

This class extends oauthlib's AuthorizationCodeGrant, rewriting
just one method, `validate_authorization_request`. It follows the
[OpenID Connect Core Spec][3]. Right now it lacks validation
of non-REQUIRED params, but this will be done soon.

We did not see the need to rewrite other methods, since they're already
generic enough or just delegate to the validator.


oidclib.grant\_types.implicit.ImplicitGrant
-------------------------------------------

This class extends oaudhlib's ImplicitGrant, and only rewrites
`validate_token_request` and `create_token_response`. Like the previous
class, it only handles the REQUIRED parts of the spec, for now.


VALIDATOR
---------

A custom validator had to be created due to some new implementation-specific
behavior of OIDC requests. The methods are documented on `oidc.validator`. Some
methods are new, and some are just being reimplemented to document they now
have an extended role.


TOKEN
-----

The oidlib's `OIDCToken` differs from oauthlib's `BearerToken` because
it returns an id\_token along with all other params. It also decides if
access\_token should be returned or not, based on requests' response_type.

[1]: http://openid.net/connect/
[2]: https://github.com/idan/oauthlib
[3]: http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
