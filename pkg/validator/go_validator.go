package validator

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

type goValidator struct {
	client *validator.Validate
}

type errorValidation struct {
	Message string `json:"message"`
}

// @note: returning first invalid error
func (v *goValidator) Validate(i interface{}) error {
	err := v.client.Struct(i)
	if err == nil {
		return nil
	}
	vErrs, ok := err.(validator.ValidationErrors)
	if !ok {
		return &ValidationError{
			Message: err.Error(),
		}
	}

	var arrErrors []string

	for _, e := range vErrs {
		arrErrors = append(arrErrors, getErrorMessage(e))
	}

	return &ValidationError{
		Message: strings.Join(arrErrors, ","),
	}
}

func NewGoValidator() *goValidator {
	return &goValidator{
		client: validator.New(),
	}
}
