# Tapis Authenticator

REST API and web server providing authentication for a Tapis v3 instance.

## Usage
This repository includes build files and other assets needed to start the service locally. Clone this
repository and follow the steps in the subsequent section.

### Start the Server Locally
We are automating the management of the lifecycle workflow with `make`. You will need to install `make` it in order
to use the steps bellow.

The make system is generic and used by multiple Tapis services. Before following any of the sections below,
be sure to

```
$ export API_NAME=authenticator
```

The `API_NAME` variable is used to let the `make` system know which Tapis service to work with.


#### First Time Setup
Starting the API the first time requires some initial setup. Do the following steps once per machine:

1. `make init_dbs` - creates a new docker volume, `authenticator_pgdata`, creates a new Postrgres
Docker container with the volume created, and creates the initial (empty) database and database user.
2. `make migrate.upgrade` - runs the migrations contained within the `migrations/versions` directory.
3. `docker-compose up -d authenticator` - starts the Authenticator.

#### Updating the API After the First Setup
Once the First Time Setup has been done a machine, updates can be fetched applied as follows:

1. `git pull` - Download the latest updates locally.
2. `make build.api` - Build a new version of the API container image.
3. `make migrate.upgade` - Run any new migrations (this step is only needed if new files appear in the `versions`
directory).migrations
4. `docker-compose up -d authenticator` - start a new version of the Authenticator.

#### New DB Schema
During initial development, the database schema can be in flux. Changes to the models require new migrations. Instead of
adding additional migration versions, the database and associated `migrations` directory can be "wiped" and recreated
from the new models code using the following steps:

1. `make wipe` - removes the database and API container, database volume, and the `migrations` directory.database
2. `make init_dbs` - creates a new docker volume, `tenant-api_pgdata`, creates a new Postrgres
Docker container with the volume created, and creates the initial (empty) database and database user.
3. Add the migrations:

```
docker run -it --rm --entrypoint=bash --network=authenticator_authenticator -v $(pwd):/home/tapis/mig tapis/authenticator
  # inside the container:
  $ cd mig; flask db init
  $ flask db migrate
  $ flask db upgrade
  $ exit
```

### Quickstart
Use any HTTP client to interact with the running API. The following examples use `curl`.

There are three primary collections supported by this API - `/clients`, `/profiles` and `/tokens`.

#### Work With Clients

Create a client with a callback URL and display name:
```
curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/oauth2/clients -H "content-type: application/json" -d '{"callback_url": "http://localhost:5000/oauth2/webapp/callback", "display_name": "Tapis Token Webapp"}'| jq

{
  "message": "Client created successfully.",
  "result": {
    "callback_url": "http://localhost:5000/oauth2/webapp/callback",
    "client_id": "0GaE2eEZRYMd",
    "client_key": "ka0zMQm5N13d",
    "create_time": "Wed, 04 Dec 2019 19:05:20 GMT",
    "description": "",
    "display_name": "Tapis Token Webapp",
    "last_update_time": "Wed, 04 Dec 2019 19:05:20 GMT",
    "owner": "jstubbs"
  },
  "status": "success",
  "version": "dev"
}

```

#### Work With The Authorization Code Grant Type

The authorization code grant type requires a pre-registered client
with a callback URL. See the "Work With Clients" section for an 
example of how to register a client.

Once the client has been registered, start the OAuth2 flow by
navigating to:

```
1) http://localhost:5000/v3/oauth2/authorize?client_id=<client_id>&redirect_uri=<redirec_uri>&response_type=code

```

For example,
```
http://localhost:5000/v3/oauth2/authorize?client_id=8dmkwnY8WkZlg&redirect_uri=http://localhost:5000/v3/oauth2/webapp/callback&response_type=code
```

This will redirect the user to the Tenant Selection form, here:

```
2) http://localhost:5000/v3/oauth2/tenant
```


You can clear your cookie-based web session using logging out page; submit
the form here:

```
http://localhost:5000/v3/oauth2/logout
``` 

#### Work With Tokens

TBD

#### Work With Profiles

List all profiles:
```
curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/oauth2/profiles
{
  "message": "Profiles retrieved successfully.",
  "result": [
    {
      "create_time": null,
      "dn": "cn=testuser1,ou=tenants.dev,dc=tapis",
      "email": "testuser1@test.tapis.io",
      "given_name": "testuser1",
      "last_name": "testuser1",
      "mobile_phone": null,
      "phone": null,
      "uid": null,
      "username": "testuser1"
    },
    . . .
    ],
  "status": "success",
  "version": "dev"    
 } 

```

Use pagination to page through the profiles:

```
curl -H "X-Tapis-Token: $jwt" 'localhost:5000/v3/oauth2/profiles?limit=1&offset=2'

{
  "message": "Profiles retrieved successfully.",
  "result": [
    {
      "create_time": null,
      "dn": "cn=testuser3,ou=tenants.dev,dc=tapis",
      "email": "testuser3@test.tapis.io",
      "given_name": "testuser3",
      "last_name": "testuser3",
      "mobile_phone": null,
      "phone": null,
      "uid": null,
      "username": "testuser3"
    }
  ],
  "status": "success",
  "version": "dev"
}

```

### Beyond the Quickstart

A complete OpenAPI v3 spec file is included in the `service/resources` directory within this repository.