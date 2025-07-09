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

Data from this app is stored in a _backend_. We support two backends, a database backend using sqlalchemy
and a Redis backend, which stores data as a json object in redis.

In `.env`, set `CONFIG_BACKEND` to `db` or `redis`.

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

5. Token exchange

    If you have the redirect URL set up to a live ngrok server, the webapp will receive the callback and exchange the tokens. If not, you can exchange them manually:

        arguments: provider code state

        uv run flask cli exchange-auth https://solidcommunity.net/ [&code= param] [&state= param]

    or with the entire URL (put the URL in quotes always to prevent & doing funny things in your shell)

        uv run flask cli exchange-auth-url "https://0934-84-89-157-10.ngrok-free.app/redirect?code=d8f7701b-fb69-4d4e-ad24-4d788dca8b55&state=penPH3QYjuoevmd8Un76590IU2TRRLM8cVyHvqWMoNo9ioDEdgA&iss=https%3A%2F%2Flogin.inrupt.com"

6. Refresh a token:

	    uv run flask cli refresh https://alastairp.solidcommunity.net/profile/card#me


# Using the library in other projects
You can use this library from another application.

The main interfaces are in the `solidauth` package.
You need to decide if you want to use the redis or the db backend:

```py
from solidauth.backend.db_backend import DBBackend
from solidauth.backend.redis_backend import RedisBackend
from solidauth.db import Base
from solidauth import client

client.set_backend(DBBackend(db.session))
client.set_backend(RedisBackend(redis_client))

# Create the database tables if you use the DBBackend
Base.metadata.create_all(db.engine)
```

## Workflow

Review the command-line steps above to see the general process that you will need to follow.
A user will come with a web-id (which is a URL). By looking up the URL you can identify the "provider" where this
webid is registered.

### 1.
Use `solidauth.authentication.generate_authentication_url` to get some information about the provider, (optionally) register
a client with it, and get a URL to sent the user to to complete the authentication request

```py
def generate_authentication_url(
    backend, webid_or_provider, registration_request, redirect_url, client_id_document_url=None
):
```

Arguments:

   - `backend`: A backend to use
   - `webid_or_provider`: The webid of the user who wants to authenticate
   - `registration_request`: If you want to perform dynamic registration (client_id_document_url is None), the contents of the registration request
   - `redirect_url`: Where you want the provider to redirect you to after the user gives you permission. This must be a URL present in the client document/registration request
   - `client_id_document_url`: If you want to use a client id document, the URL to this document. Use `None` to perform dynamic registration

Dynamic registration creates an openid client on the fly and returns a client id and secret which can be used as you
would "normally" do with openid. Alternatively, solid allows you to use a "client id document", where you
specify a URL in your client_id, and you have no client_secret.

If you want to use Client ID Documents then you need to provide a public endpoint which serves the
document with a `Content-Type: application/ld+json` header. See `solid/__init__.py` and `solid.webserver.client_id_url()`
for an example of this document. Note that the document needs to include its own URL as the `"client_id"` field.
More documentation on registration is available at https://solidproject.org/TR/oidc#clientids

If you set `client_id_document_url` to `None`, then this method will automatically perform a client registration
using the data in `registration_request`, and will store the client information to the backend.
See more about dynamic registration at https://openid.net/specs/openid-connect-registration-1_0.html

The method will save a PKCE state and code in the backend and return the URL that you need to send the user to.


### 2.
At the redirect url, use `solidauth.authentication.generate_authentication_url` to perform PKCE validation and key exchange

```py
def authentication_callback(
    backend, auth_code, state, provider, redirect_uri, base_url, always_use_client_id_document=False
):
```

Arguments:
  - `backend`: A backend to use
  - `auth_code`: The PKCE `code` GET parameter returned in the callback URL
  - `state`: The PKCE `state` GET parameter returned in the callback URL
  - `provider`: The provider that you were redirected from. Some providers pass this in the `iss` GET parameter,
    but if not then you should store it in a client state at the previous step and retrieve it.
  - `redirect_uri`: The URL of this endpoint
  - `client_id_document_url`: As above

### 3.

To make an authenticated request as this user, use `solidauth.client.get_bearer_for_user` to get the headers needed for this request
Make sure you use `client.set_backend` first (yes, this is inconsistent with the `solidauth.authentication` package)

```py
def get_bearer_for_user(provider, profile, url, method, client_id_document_url=None):
```

Arguments:
  - `provider`: The provider that the user authenticated at
  - `profile`: The web id of the user making the request
  - `url`: The URL of the request
  - `method`: The HTTP method of the request
  - `client_id_document`: Set to a client id document if using this, otherwise set to `None` to use the client for this provider which
    was created with dynamic registration.

```py
    provider = "https://solidcommunity.net/"
    profile = "https://username.solidcommunity.net/profile/card#me"
    container = "https://username.solidcommunity.net/location/"
    client_id_document = "https://example.com/solid-client.jsonld"
    headers = get_bearer_for_user(provider, profile, container, "OPTIONS", client_id_document_url)
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