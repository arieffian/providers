package jwt

// redis keys | auth
const (
	AUTH_ATTEMPT_KEY       = "|auth:otp:attempt:%s|"
	AUTH_CRED_KEY          = "|auth:cred:%s|"
	REVOKED_TOKEN_KEY      = "|auth:revoked-token:jti:%s|"
	AUTH_STORE_KEY         = "|auth:store:%s:%s:%s|"
	REGISTRATION_EMAIL_KEY = "|auth:registration:%s:%s|"
	BIND_EMAIL_KEY         = "|auth:bind:%s:%s:%s|"
)
