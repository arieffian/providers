package validator

import (
	"context"

	validator_pkg "github.com/go-playground/validator/v10"
)

type ValidatorService interface {
	Validate(ctx context.Context, i interface{}) error
}

type validatorService struct {
	validator *validator_pkg.Validate
}

func NewValidatorService() ValidatorService {
	v := validator_pkg.New()

	return &validatorService{
		validator: v,
	}
}

func (v *validatorService) Validate(ctx context.Context, i interface{}) error {
	return v.validator.Struct(i)
}
