# Change Log
All notable changes to this project will be documented in this file.

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
