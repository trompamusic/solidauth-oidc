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