package validator

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

type Validator interface {
	Validate(i interface{}) error
}

func getErrorMessage(e validator.FieldError) (message string) {
	switch e.Tag() {
	case "required":
		message = fmt.Sprintf("'%s' is %s!", e.Field(), e.Tag())
	case "email":
		message = "Please input a valid email!"
	case "len":
		message = fmt.Sprintf("'%s' should be exactly %s character(s) or %s item(s)!", e.Field(), e.Param(), e.Param())
	case "max":
		message = fmt.Sprintf("'%s' may not be more than %s character(s) or %s item(s)!", e.Field(), e.Param(), e.Param())
	case "min":
		message = fmt.Sprintf("'%s' should be at least %s character(s) or %s item(s)!", e.Field(), e.Param(), e.Param())
	case "alphanum":
		message = fmt.Sprintf("'%s' may just contains alphabet and numeric!", e.Field())
	case "number":
		message = fmt.Sprintf("'%s' should be a number!", e.Field())
	case "gt":
		message = fmt.Sprintf("'%s' field value should be greater than %s!", e.Field(), e.Param())
	case "gte":
		message = fmt.Sprintf("'%s' field value should be greater than or equal %s!", e.Field(), e.Param())
	case "lt":
		message = fmt.Sprintf("'%s' field value should be less than %s!", e.Field(), e.Param())
	case "lte":
		message = fmt.Sprintf("'%s' field value should be less than or equal %s!", e.Field(), e.Param())
	case "unique":
		message = fmt.Sprintf("'%s' field value has already been taken!", e.Field())
	default:
		message = fmt.Sprintf("'%s' field validation failed on '%s' tag!", e.Field(), e.Tag())
	}

	return
}
