# Change Log
All notable changes to this project will be documented in this file.


## 1.6.0 - 2024-02-06 (estimated)

### Breaking Changes:
- None

### New features:
- None 

### Bug Fixes:
- Fix issue impacting the implicit grant type from working in cases where the tenants
  has configured an LDAP authentication due to response_type being dropped from the login UI. See issue #66 for more details. 

## 1.5.1 - 2023-10-27

### Breaking Changes:
- None

### New features:
- Added a new /v3/oauth2/webapp/logout endpoint for testing with the Token Webapp; it removes only the token from the 
  session, while keeping the authorization server's session in tact. This allows for using the Token Webapp to test 
  repeated logins within the same authorization server session. 

### Bug Fixes:
- Fix bug where, for tenants configured with custom OA2 IdPs, a second attempt to authenticate a user via an OAuth2 flow
  after a user had already authenticated with a previous client (and had established a session) would fail. The issue is 
  that, in 1.5.0, we remove the orig_client_* attributes from the session on successful login; however, for custom OA2
  IdPs, we expect to get the client_id out of the session. This will fail on the first call to /authorize in such cases.


## 1.5.0 - 2023-10-17

### Breaking Changes:
- None

### New features:
- Tenants are now able to determine how long the MFA authentication should last before the user has to re-enter their MFA
- Updated HTML - all of the different pages of the authentication workflow now have updated design layouts

### Bug Fixes:
- The device code flow, starting with GET /v3/device?client_id=<client_id>, is now working for all login methods
- The language for the user code form of the device flow is now more clear


## 1.4.0 - 2023-07-17
There were no major updates in this release.

### Breaking Changes:
- None

### New features:
- None

### Bug fixes:
- None


## 1.3.5 - 2023-06-27 (target)
### Breaking Changes:
- The DELETE /v3/oauth2/clients endpoint now returns the standard 5-stanza Tapis response. Previously, it returned
an empty HTTP response. Applications that use this endpoint should be updated to handle a non-empty response.
- The POST /v3/oauth2/tokens endpoint has been changed in the case of the device_code grant to require only the client_id as a POST parameter. Previously, the client_id and client_key were erroneously both required to be passed using an HTTP Basic Auth header. Client applications that utilized the device code grant type and passed the client credentials as part of the HTTP Basic Auth header must be updated to pass only the client id as part of the POST payload. The OA3 spec has been updated to reflect this new requirement. See issue #32.

### New features:
- By default, an account with username "admin" is now created in the dev tenant (see issue #33).
- Upgrade to tapipy 1.4.0 and associated library upgrades (e.g., openapi-core 0.16 from 0.12). This upgrade improves spec loading times and reduces the overall time for the authenticator service to start up. See issue #31.

### Bug fixes:
- The POST /v3/oauth2/tokens endpoint has been changed in the case of the device_code grant to require only the client_id as a POST parameter. Previously, the client_id and client_key were erroneously both required to be passed using an HTTP Basic Auth header. Client applications that utilized the device code grant type and passed the client credentials as part of the HTTP Basic Auth header must be updated to pass only the client id as part of the POST payload. The OA3 spec has been updated to reflect this new requirement. See issue #32.
- The OA3 spec has been updated to correct the DELETE /v3/oauth2/clients endpoint (it was mislabeled "Delete a tenant") and to specify the TapisJWT authentication on endpoints that require it (see issue #34)


## 1.3.4 - 2023-05-30
### Breaking Changes:
- None

### New features:
- None

### Bug fixes:
- This release fixes some issues with the device code flow, including when generating a device code and 
  when using device codes with non-ldap identity providers. 
- This release also fixes a bug in the OAuth2ProviderExtCallback controller where the append_idp_to_username was not defined if the ext type was not "multi_idps". This bug impacted tenants such as CII with a different custom IdP type.


## 1.3.3 - 2023-05-11
### Breaking Changes:
- None

### New features:
- Update the oa3 spec with a comment to indicate that Profile fields are optional; add check for custom idp types and still try to get the profile fields in those cases.

### Bug fixes:
- None


## 1.3.2 - 2023-05-08
### Breaking Changes:
- None

### New features:
- None

### Bug fixes:
- Fix an issue where the tenant_config_cache was leaving an access share relation (table) lock on the table indefinitely, preventing alter table commands from completing. 


## 1.3.1 - 2023-05-02

### Breaking Changes:
- None

### New features:
- Add support for "multi_keycloak" OAuth extension type, allowing tenants to configure arbitrary KeyCloak
  instances.
- Add support for "globus" OAuth extension type, enabling use of Globus Auth/CILogon without KeyCloak.
- Add support for "multi_idps" extension type, enabling tenants to configure multiple identity provider 
  backends including: GitHub, KeyCloak, Globus, LDAP, etc.
- Updates to the HTML in the example token web app.

### Bug fixes:
- None


## 1.3.0 - 2023-03-12
This production point release adds support for TACC MFA, token revocation, token tracking 
for usage analytics and a number of bug fixes. 
NOTE: This version of Authenticator depends on the Site Router API for Token revocation, not
previously released. 

### Breaking Changes:
- None; Site Router is now required for revocation endpoints to function.

### New features:
- Suport for TACC MFA
- Support for Token revocation.
- Support for usage analytics via token tracking. 
- Add support for configuring Tokens to serve all tenants at a site via the `tenants: ["*"]` configuration.

### Bug fixes:
- Fix a bug in the way authenticator called `jwt.decode` when decoding a CII token. Due to a recent upgrade to the Python JWT library in flaskbase, we must specify the algorithm used to decode -- in this case, `HS256`. (originally released in 1.2.1)


## 1.2.5 - 2022-09-15
This preview release adds support for tracking tokens generated in SQL, including access and refresh token.
This feature allows users to compute usage data such as how many distinct users generated access tokens in
each tenant.

### Breaking Changes:
- None.

### New features:
- Adds new SQL tables for tracking access tokens and refresh tokens generated by authenticator (#22). 
- Add additional indexes to the Clients and TenantConfigs table; (this update provided as a separate migration).

### Bug fixes:
- None.



## 1.2.4 - 2022-08-24
This preview release adds support for token revocation. See issue #7 for more details.

### Breaking Changes:
- None.

### New features:
- Adds a new endpoint for revoking a Tapis user JWT.

### Bug fixes:
- None.


## 1.2.3 - 2022-08-2
This is a bug fix release that corrects a small issue with the MFA feature.

### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- Fixes an issue with the MFA feature where tenants could be prompted for MFA even if they were not configured for it.


## 1.2.2 - 2022-07-29
This preview release adds support for the TACC MFA solution, which can be configured for tenants using the 
TACC identity provider (TACC LDAP) on a tenant by tenant basis. It also adds a new endpoint for exchanging 
a v3 access token for a Tapis v2 token. This feature is also only available for certain tenants. 

### Breaking Changes:
- None.

### New features:
- Support for TACC MFA via PrivacyIdea API (requires configuration for each tenant)
- Support for exchanging Tapis v3 tokens for Tapis v2 tokens (requires configuration for each tenant).

### Bug fixes:
- None.


## 1.2.1 - 2022-06-09
This patch release fixes an issue with the CII authenticator plugin that was introduced by an upgrade to the
Python JWT library.

### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- Fix a bug in the way authenticator called `jwt.decode` when decoding a CII token. Due to a recent upgrade to the Python JWT lobrary in flaskbase, we must specify the algorithm used to decode -- in this case, `HS256`.


## 1.2.0 - 2022-05-30
This release adds support for the device code grant type and OAuth2 authentication
via TACC's Keycloak instance to support third-party identity providers, including
Globus Auth.

### Breaking Changes:
- None.

### New features:
- Add support for the device code grant type (https://datatracker.ietf.org/doc/html/rfc8628) and with it, the ability to generate long-lived tokens. See issue #6 for
more details.
- Adds support for authenticating via TACC's Keycloak instance. This authentication
mechanism is used when a tenant configures a custom idp configuration of type `tacc_keycloak`. See issue #18 for more details.
- Adds health check and ready endpoints.

### Bug fixes:
- Fix a bug in the way authenticator computed the `default_user_filter_prefix` that was causing two equals signs (`=`) to get inserted into the filter. 


## 1.1.0 - 2022-03-01
This release converts the Authenticator to using the new `tapipy-tapisservice` plugin-based 
Tapis Python SDK and makes updates necessary for supporting deployment automation provided
by the Tapis Deployer project.

### Breaking Changes:
- None.

### New features:
- Convert Authenticator to using the new `tapis/flaskbase-plugins` image.
- Support the initial version of the Tapis Deployer deployment automation. 
- Add support for utilizing the `dev` ldap (with test accounts) on an arbitrary tenant, not
  just the `dev` tenant, so that it can be utilized by different sites.

### Bug fixes:
- None.



## 1.0.2 - 2021-07-16
### Breaking Changes:
- None.

### New features:
- Added support for the implict grant type (https://github.com/tapis-project/authenticator/issues/5). This feature is in "preview".
- Added support for sending www-form encoded requests to the tokens endpoint (https://github.com/tapis-project/authenticator/issues/10). 
- Added support for OAuth metadata discovery endpoint. (https://github.com/tapis-project/authenticator/issues/11)

### Bug fixes:
- None.


## 1.0.1 - 2021-07-16
### Breaking Changes:
- None.

### New features:
- None.

### Bug fixes:
- Fix bug where API request would result in an uncaught sqlalchemy detached instance error (see https://github.com/tapis-project/authenticator/issues/4)


## 1.0.0 - 2021-07-16
Initial production release of Tapis Authenticator with support for OAuth2 password 
and authorization code grant types and authentication with LDAP servers.

For more details, please see the documentations: https://tapis.readthedocs.io/en/latest/technical/authentication.html

Live-docs: https://tapis-project.github.io/live-docs/

### Breaking Changes:
- Initial release.

### New features:
 - Initial release.

### Bug fixes:
- None.


## 0.1.0 - 2019-11-10 (target)
### Added
- Initial alpha release.

### Changed
- No change.

### Removed
- No change.
