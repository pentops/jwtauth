# JWT Auth

JWT Auth has three major components in it, each each of which plays a part in
the authentication process for services running in an O5 controlled setup.

## Keys
The ease of parsing, encoding, and generating a keys for use in services or a middleware.

## gRPC Middleware
The middleware is to provide an easy means of whether or not a valid JWT token is
present in the request. In particular this is what the o5 sidecar uses to ensure
all requests are authenticated.

## Service
The service is a configurable http server to host the JWKS well-known endpoint
for the sidecars and any auth services to leverage.
