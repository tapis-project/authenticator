# Tapis Authenticator

REST API and web server providing authentication for a Tapis v3 instance.

## Usage
This repository includes build files and other assets needed to start the service locally. Clone this
repository and follow the steps in the subsequent section.

### Start the Server Locally
First, make sure the following passwords are set correctly.

1. Within ``config-local.json``, update the ``service_password`` to match the authenticator's service_password stored in the SK
   in develop.
2. Within ``docker-compose.yml``, update the ``LDAP_ROOTPASS`` to match the ``password`` key in the secret ``ldap.tapis-dev`` stored in SK.

#### Working With Secrets in the SK ####
We are now storing LDAP secrets within the SK. To retrieve them, use the Python SDK with a token representing the
authenticator. For example:

List all secrets:

```
>>> t.sk.listSecretMeta(secretType='user', tenant='admin', user='authenticator', _tapis_set_x_headers_from_service=True)
```

Retrieve the dev LDAP secret from SK and get the password:

```
>>> s = t.sk.readSecret(secretType='user', secretName='ldap.tapis-dev', tenant='admin', user='authenticator', _tapis_set_x_headers_from_service=True)
>>> s.secretMap.password
```



We are automating the management of the lifecycle workflow with `make`. You will need to install `make` it in order
to use the steps bellow.

The make system is generic and used by multiple Tapis services. Before following any of the sections below,
be sure to run:

```
$ export API_NAME=authenticator
```

Alternatively, create a `.env` file with the content `API_NAME=authenticator`.

The `API_NAME` variable is used to let the `make` system know which Tapis service to work with.


#### First Time Setup
Starting the API the first time requires some initial setup. Do the following steps once per machine:

1. `make init_dbs` - creates a new docker volume, `authenticator_pgdata`, creates a new Postrgres
Docker container with the volume created, and creates the initial (empty) database and database user.
2. `make migrate.upgrade` - runs the migrations contained within the `migrations/versions` directory.
3. `docker-compose up -d authenticator` - starts the Authenticator.

#### Running the Tests
You can run the tests on your local machine using the following:

```
make clean
make build
make init_dbs
make migrate.upgrade
make test
```
Note that this will remove the 

#### Updating the API After the First Setup
Once the First Time Setup has been done a machine, updates can be fetched applied as follows:

1. `git pull` - Download the latest updates locally.
2. `make build.api` - Build a new version of the API container image.
3. `make migrate.upgrade` - Run any new migrations (this step is only needed if new files appear in the `versions`
directory).migrations
4. `docker-compose up -d authenticator` - start a new version of the Authenticator.

#### Updates to the Existing Schema
If you change any of the SQL table schemas, either via a change to one of the existing `db.model` classes or a new 
`db.models` class in `models.py`, you will need to generate a new migration version. We use alembic to manage
migrations. Here are the steps:

0. First, start up the authenticator stack (including postgres database) as is, before making any changes. Check
   that there are no problems with your existing checkout/development environment. 
1. Make changes to the models.py file to reflect the updates you want to make.
2. Rebuild the containers (``make build``), specifically need the migrations container to be rebuilt.
3. Shut down all the services (``make clean``).
4. Start up the db containers (``make init_dbs``).
5. Run the existing migrations (``make migrate.upgrade``).
6. Exec into a new migrations container:
   docker run -it --entrypoint=bash --network=authenticator_authenticator tapis/authenticator-migrations
7. Once inside the container:
  $ flask db migrate
  $ flask db upgrade   
Note that the migrate step should create a new migration Python source file in /home/tapis/migrations/versions/
Note also that the upgrade step (that applies the generated file) could fail if, for example, your changes include 
a new, non-nullable field. For such changes, you will need to make custom changes to the migration Python source
file. 
8. Back outside of the container, copy the migration file to the migrations directory within this repo.
9. Be sure to update the migrations Python source file, as needed. There are good references on the web for how to 
do this; see, for example, https://medium.com/the-andela-way/alembic-how-to-add-a-non-nullable-field-to-a-populated-table-998554003134
   


#### Configuring Custom IdPs
When testing the custom IdP configurations (for example, for the github-demo or icicle tenants), 
one needs to store the configuration into the local postgres databse. Here are the steps to do that:

##### GitHub
Exec into the authenticator Python container and run the following:

```
<from within the container>
python
from service.models import TenantConfig, db
import json
c = TenantConfig.query.filter_by(tenant_id='github-demo')[0]
d = {'github': { 'client_id': '<get_from_stache>', 'client_secret': '<get_from_stache>'}}
s = json.dumps(d)
c.custom_idp_configuration = s
db.session.commit()

```


##### ICICLE

Exec into the authenticator Python container and run the following:

```
<from within the container>
python
from service.models import TenantConfig, db
import json
c = TenantConfig.query.filter_by(tenant_id='icicle')[0]
d = {'tacc_keycloak': { 'client_id': '<get_from_stache>', 'client_secret': '<get_from_stache>'}}
s = json.dumps(d)
c.custom_idp_configuration = s
db.session.commit()

```

#### Configuring MFA Config
When testing the MFA config (for example, for the jupyter-tacc-dev tenant) using TACC auth, 
one needs to store the configuration in the local postgres databse. Here are the steps to do that:

##### Jupyter TACC Dev
Exec into the authenticator Python container and run the following:

```
<from within the container>
python
from service.models import TenantConfig, db
import json
c = TenantConfig.query.filter_by(tenant_id='jupyter-tacc-dev')[0]
d = {"tacc": {"grant_types": [], "privacy_idea_client_id": "<get_from_stache>", "privacy_idea_client_key": "<get_from_stache>", "privacy_idea_url": "https://pidea02.tacc.utexas.edu", "realm": "tacc"}}
c.mfa_config = json_dumps(d)
db.session.commit()
```



#### New DB Schema

*** DEPRECATED -- should use Updates to the Existing Schema from now on.***

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

### API Quickstart
Use any HTTP client to interact with the running API. The following examples use `curl`.

There are three primary collections supported by this API - `/clients`, `/profiles` and `/tokens`.
Most of the functionality contained within the authenticator requires an OAuth client.


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

### Beyond the API Quickstart

A complete OpenAPI v3 spec file is included in the `service/resources` directory within this repository.


### Using the Token Web Application
This project includes a basic "Token Web Application" that can be used to demonstrate
the authorization_code flow in a real application and can be used by any user wanting to 
retrieve an access token using a graphical interface.

There are different entrypoints to the application, but for a simple start:

```
1) Navigate to http://localhost:5000/v3/oauth2/webapp
``` 

This should redirect your browser to the "Login App" which should provide you with a 
form to enter your username and password. It should also display the tenant that you
are interacting with, in this case, "dev".

#### Why is it the "dev" Tenant?
In general, the Token Web Application is "multi-tenant", and the tenant is derived 
from the base URL. When running locally during development, the base URL is always
"localhost", so the application defaults to using the "dev" tenant in that case.

In order to use a different tenant when running the Authenticator locally, use the
tenant selector page, 
```
Navigate to http://localhost:5000/v3/oauth2/tenant to select a different tenant.
```

Once you have selected the tenant you wish to work in, you will be prompted to log in.
If using the dev tenant, be sure to enter valid credentials for a test account. If using 
the TACC tenant, you should be able to enter your TACC credentials.
  
```
2) Enter your username and password
```

After entering the credentials, you should be redirected to an "Authorize" page where you will be asked
to authorize the client to 

```
3) Submit approve to authorize the Tapis Token Webapp client application to request an access 
token ob your behalf. 
```

Once you submit the approval, you should be redirected to a page displaying your Tapis token. The token is 
a JWT that includes claims corresponding to the user and OAuth client that authenticated.
 

#### Work With The Authorization Code Grant Type In Your Own Application

The authorization code grant type requires a pre-registered client
with a callback URL. See the "Work With Clients" section for an 
example of how to register a client.

Once the client has been registered, start the OAuth2 flow by
redirecting your user to the /oauth2/authorize URL and passing the following:
```
client_id=<your_client_id>
redirect_uri=<your_redirect_uri>
response_tyep=code
```

For example:
```
1) GET http://localhost:5000/v3/oauth2/authorize?client_id=<client_id>&redirect_uri=<redirec_uri>&response_type=code

```

This authorize endpoint will redirect the user to either the login form if they have not yet
authenticated with the Authenticator or to the authorize form if they have previously authenticated:

```
2) http://localhost:5000/v3/oauth2/login
```

Once the user has logged in and approved the request from you client application, the Authenticator
will make a GET request to your client's callback URL, passing the authorization code as a query parameter called "code".

```
3) GET http://localhost:5000/v3/oauth2/webapp/callback?code=<some_code>
``` 

Your client application code should handle this GET request by making a request to the `/oauth2/tokens` endpoint to exchange
the authorization code for an OAuth token. 

```
4) POST http://localhost:5000/v3/oauth2/token
        grant_type=authorization_code
        code=<some_code>
        redirect_uri=<your_redirct_uri>
```


#### Work With Tokens

The Authenticator supports OAuth2 flows for generating access (and in some cases, refresh) tokens.
THe grant types require basic authentication with a valid Tapis OAuth client, however, one can 
use the password grant without a Tapis client to first get a token.




