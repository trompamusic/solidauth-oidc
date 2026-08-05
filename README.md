# Solid application auth

This is a demo of [Solid OIDC](https://solid.github.io/solid-oidc/)
authentication to a [SOLID](https://solidproject.org/) server.


### License
This project is available under the terms of the BSD 3-clause license. See LICENCE for more details

# Setup

## Dependencies

Use `uv` to install dependencies:

    uv sync

## Configuration

To configure the application, copy the `.env.sample` file

### Backends

Data from this app is stored in a database backend using SQLAlchemy.

# Running

## Web version

Start the flask webserver to perform a login process. If you want to use a client id document for authentication
then you must run the webserver and also have a public tunnel running (see "Callback urls" below)

    FLASK_DEBUG=1 uv run flask run

Visit http://localhost:5000/ to start the auth flow for a given solid web id

## Commandline version

We have a set of commandline tools to perform the steps needed to perform an authentication workflow, mostly for debug purposes.

1. create local keys (only needs to be done once)

       uv run flask cli create-key

2. register a provider using one of the following two options

    This gets the provider for the profile, and gets configuration options

        uv run flask cli get-provider-configuration-from-profile https://username.solidcommunity.net/profile/card#me

    or (if you don't know a profile id, or you know the provider url)

        uv run flask cli get-provider-configuration https://solidcommunity.net/

3. register a client with the provider. This option is only needed if you want to use dynamic registration. If you use client id documents then it's not necessary.

       uv run flask cli register https://solidcommunity.net/

4. Sign in/auth with a user, passing in the profile of the user you want to auth as. It will find the provider by looking it up in the card.

       uv run flask cli auth-request https://alastairp.solidcommunity.net/profile/card#me

    Follow url that is printed, sign in, and authorize the request.

    To sign in with a client ID document, ensure that `CONFIG_BASE_URL` is accessible from the internet and run:

        uv run flask cli auth-request --use-client-id-document https://alastairp.solidcommunity.net/profile/card#me

5. Token exchange

    If you have the redirect URL set up to a live ngrok server, the webapp will receive the callback and exchange the tokens. If not, you can exchange them manually:

        uv run flask cli exchange-auth [--use-client-id-document] CODE STATE https://solidcommunity.net/

    or with the entire URL (put the URL in quotes always to prevent & doing funny things in your shell)

        uv run flask cli exchange-auth-url [--use-client-id-document] "https://0934-84-89-157-10.ngrok-free.app/redirect?code=d8f7701b-fb69-4d4e-ad24-4d788dca8b55&state=penPH3QYjuoevmd8Un76590IU2TRRLM8cVyHvqWMoNo9ioDEdgA&iss=https%3A%2F%2Flogin.inrupt.com"

    Use `--use-client-id-document` if the authorization request used a client ID document.

6. Refresh a token:

	    uv run flask cli refresh [--use-client-id-document] https://alastairp.solidcommunity.net/profile/card#me


# Using the library in other projects
You can use this library from another application.

The main interfaces are in the `solidauth` package.

```py
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from solidauth import client, solid
from solidauth.backend.db_backend import DBBackend
from solidauth.db import Base

# Supports sqlite or postgresql
engine = create_engine("sqlite:///solidauth.db")

# Create the database tables
Base.metadata.create_all(engine)

session = Session(engine)
backend = DBBackend(session)

# Create the key used for DPoP proofs and token exchange
if not backend.get_relying_party_keys():
    backend.save_relying_party_keys(solid.generate_keys())

sc = client.SolidClient(backend, use_client_id_document=True)
```

The application should handle the SQLAlchemy engine and session lifecycle.

Keep the value of `use_client_id_document` consistent throughout the app.

## Set a user agent

Call `set_user_agent` once at startup. If you don't do this then the default "solidauth/0.1.0"
will be used.

```py
from solidauth import httpclient

httpclient.set_user_agent("MyApp/1.0 (+https://example.org/myapp; me@example.org)")
```

## Workflow

Review the command-line steps above to see the general process that you will need to follow.
A user will come with a web-id (which is a URL). By looking up the URL you can identify the "provider" where this
webid is registered.

### 1.
Use `SolidClient.generate_authentication_url` to discover the provider, register a client when needed, and create an
authorization URL.

```py
def generate_authentication_url(
    self, webid_or_provider, registration_request, redirect_url, client_id_document_url=None
):
```

Arguments:

- `webid_or_provider`: The WebID of the user who wants to authenticate, or the URL of their provider.
- `registration_request`: The contents of the dynamic registration request. It is ignored when using a client ID
  document or when a dynamic registration for the provider is already stored.
- `redirect_url`: Where the provider should redirect the user after authorization. Use the same value in
  `authentication_callback`.
- `client_id_document_url`: The URL of the client ID document. Use `None` to use dynamic registration.

With `client_id_document_url=None`, the method reuses a stored dynamic registration or creates one using
`registration_request`. Dynamic registration provides a client ID and secret. A client ID document instead uses its
URL as the client ID and has no client secret.

If you want to use Client ID Documents then you need to provide a public endpoint which serves the
document with a `Content-Type: application/ld+json` header. See `soliddemo.webserver.client_id_url()`
for an example of this document. Note that the document needs to include its own URL as the `"client_id"` field.
More documentation on registration is available at https://solidproject.org/TR/oidc#clientids

See more about dynamic registration at https://openid.net/specs/openid-connect-registration-1_0.html

The method returns a dictionary containing `provider`, `auth_url`, and diagnostic `log_messages`. Redirect the user
to `auth_url` to authenticate and authorize the application.

### 2.
At the redirect URL, use `SolidClient.authentication_callback` to perform PKCE validation and exchange the
authorization code for tokens.

```py
def authentication_callback(
    self, auth_code, state, provider, redirect_uri, client_id_document_url=None
):
```

Arguments:

- `auth_code`: The `code` GET parameter returned in the callback URL.
- `state`: The `state` GET parameter returned in the callback URL.
- `provider`: The provider from which the user was redirected, usually provided in the `iss` GET parameter. Pass
  `None` to use the provider that `generate_authentication_url` stored with the state.
- `redirect_uri`: The URL of this callback endpoint. It must be the same value passed to
  `generate_authentication_url`.
- `client_id_document_url`: The exact client ID document URL passed to `generate_authentication_url`. Leave it as
  `None` when using dynamic registration.

The method returns `(True, token_response)` and stores the tokens on success. Handled token-exchange and validation
failures return `(False, error_response)`; configuration and network failures may raise exceptions. State is consumed
before the exchange, so start a new authentication flow after any failure.

### 3.

Use `SolidClient.get_bearer_for_user` to create the headers for an authenticated request. It refreshes an expired
access token automatically.

```py
def get_bearer_for_user(self, provider, profile, url, method):
```

Arguments:

- `provider`: The provider at which the user authenticated.
- `profile`: The WebID of the user making the request.
- `url`: The exact URL of the request.
- `method`: The exact HTTP method of the request.

The URL and method are embedded in the DPoP proof and must match request you make. The method raises
`NoSuchAuthenticationError` if it has no authentication for this user, and `TokenRefreshFailed` when an expired
token cannot be refreshed.

```py
import requests

provider = "https://solidcommunity.net/"
profile = "https://username.solidcommunity.net/profile/card#me"
container = "https://username.solidcommunity.net/location/"
headers = sc.get_bearer_for_user(provider, profile, container, "OPTIONS")
r = requests.options(container, headers=headers)
```


# Solid-OICD Notes

## Spec compliance

Solid-OIDC is still an evolving standard. Therefore we cannot guarantee full compliance with the specification. We have tested this library
with the following solid provider software:

 - ESS (Enterprise solid server)
 - CSS (Community solid server)
 - Pivot (CSS fork)
 - NSS (Node solid server)
 - Trinpod

We know of the following issues with some providers and with our implementation:

 - We do not check the features that a provider supports before trying to do a registration, and modifying our request to contain only these features
 - NSS does not support client id documents

# Acknowledgements

Some of this code was taken from the [solid-flask](https://gitlab.com/agentydragon/solid-flask) project.

This project has received funding from the European Union's Horizon 2020 research and innovation programme
H2020-EU.3.6.3.1. - Study European heritage, memory, identity, integration and cultural interaction and translation,
including its representations in cultural and scientific collections, archives and museums, to better inform and
understand the present by richer interpretations of the past under grant agreement No 770376.


# Development notes

### Database migrations

We have no method of making database migrations. If you want to make a change to the schema then you must
delete the database and re-create it, or apply the migration manually. Create the database like this:

    dropdb solid_oidc && createdb solid_oidc
    uv run flask create-db

### Callback urls

If you want to automatically handle auth callbacks, or use a client id document, then you need an external tunnel.
You can use ngrok for this, the free version is enough:

Run ngrok to point to your local flask server

    ngrok http 5000

Copy the public URL (it'll change each time you run it if you're on the free version). In `.env`
set `CONFIG_REDIRECT_URL` and `CONFIG_BASE_URL`.

Restart the flask server


### Database admin
There is a flask-admin interface that allows you to inspect the contents of the database if you're using
the `db` backend.

Create an admin user (this is completely separate from solid users)

    uv run flask create-user

Visit the admin at http://localhost:5000/admin

### Database cleanup

To remove auth details for a specific user on a specific solid provider

    delete from configuration_token

To remove our registered "app" from a solid provider

    delete from client_registration

To remove all records of a solid provider

    delete from resource_server_keys
    delete from resource_server_configuration


# Compatibility

We've tested this app with

- Community Solid Server (solidcommunity.net)
- Enterprise Solid Server (inrupt pod spaces)
- use.id
- Trinpod
- datapod.igrant.io

Node solid server (NSS) does not support client id documents.
