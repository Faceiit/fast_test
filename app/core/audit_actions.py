class AuditAction:
    AUTH_LOGIN = "auth.login"
    AUTH_API_KEY = "auth.api_key"

    SERVICE_ACCOUNT_CREATED = "service_account.created"

    SECRET_CREATED = "secret.created"
    SECRET_READ = "secret.read"
    SECRET_ROTATED = "secret.rotated"
    SECRET_DELETED = "secret.deleted"

    POLICY_CREATED = "policy.created"


class AuditStatus:
    SUCCESS = "success"
    DENIED = "denied"
    FAILED = "failed"