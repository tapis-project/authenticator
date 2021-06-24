from common.errors import BaseTapisError


class InvalidPasswordError(BaseTapisError):
    pass


class InvalidTenantUserError(BaseTapisError):
    pass


class InvalidAuthorizationCodeError(BaseTapisError):
    pass
