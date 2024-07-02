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

// redis keys | mooc dashboard
const (
	MOOC_USER_LIST   = "|mooc:dashboard:user-list:%s|"
	MOOC_COURSE_LIST = "|mooc:dashboard:course-list:%s|"
)

// otp related
const (
	CHALLENGE_METHOD = "S256"
	WA_OTP_METHOD    = "wa"
	SMS_OTP_METHOD   = "sms"
)

// environment name
const (
	ENVIRONMENT_PROD  = "prod"
	ENVIRONMENT_DEV   = "dev"
	ENVIRONMENT_STG   = "stg"
	ENVIRONMENT_LOCAL = "local"
)

// regex pattern
const (
	PHONE_NUMBER_REGEXP       = `^\+(\d{1,2})(\d{4,})$`
	DUMMY_PHONE_NUMBER_REGEXP = `^\+(xx)?(\d{1,2})(\d{4,})$`
	EMAIL_REGEX               = `^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$`
)

// authentication issuer
const (
	CIAM_WEB_TOKEN_ISSUER    = "https://am:443/am/oauth2/tsel/kuncie/web"
	CIAM_MOBILE_TOKEN_ISSUER = "https://am:443/am/oauth2/tsel/kuncie/mobile"
	KUNCIE_TOKEN_ISSUER      = "kuncie"
)

// token audience
const (
	WEB_AUDIENCE    = "kuncie-web"
	TV_AUDIENCE     = "kuncie-tv"
	MOBILE_AUDIENCE = "kuncie-mobile"
)

// auth provider slugs
const (
	CIAM_PROVIDER_SLUG     = "ciam"
	KUNCIE_PROVIDER_SLUG   = "kuncie"
	AUTH0_PROVIDER_SLUG    = "auth0"
	COGNITO_PROVIDER_SLUG  = "cognito"
	INDIHOME_PROVIDER_SLUG = "indihome"
)

// client type
const (
	CLIENT_TYPE_WEB    = "web"
	CLIENT_TYPE_MOBILE = "mobile"
	CLIENT_TYPE_TV     = "tv"
)

var ValidClientType = map[string]string{
	"web":    CLIENT_TYPE_WEB,
	"mobile": CLIENT_TYPE_MOBILE,
	"tv":     CLIENT_TYPE_TV,
}
