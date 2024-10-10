# koonetto-auth-server


See the list of important urls here: http://localhost:8181/.well-known/openid-configuration

- client credentials : communication between microservices or backend api
- authorization code : communication where the user is involved and the  secret is fully handled by the backend application
- authorization code + pcke : communication where the client is an application that cannot store secrets such as SPA, MOBILE, REACT or ANGULAR applications

This token uses JWKs, not opaque tokens