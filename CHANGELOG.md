# Change Log
All notable changes to this project will be documented in this file.


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
