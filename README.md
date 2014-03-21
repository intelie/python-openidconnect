OIDClib (WIP)
=============

An implementation of [OpenID Connect][1] for Python, on top of [OAuthlib][2].


HOW TO USE IT
-------------

Just replace your OAuthlib server for this:

    from oauthlib.oauth2 import Server
    from oidclib import oidc_endpoint

    server = oidc_endpoint(Server)

[1]: http://openid.net/connect/
[2]: https://github.com/idan/oauthlib
