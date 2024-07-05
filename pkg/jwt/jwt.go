package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/arieffian/providers/pkg/redis"
	go_jwt "github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

type TokenType int

const (
	Unknown TokenType = iota
	AuthId
	AccessToken
	RefreshToken
	IdToken
)

var _ JwtService = (*jwtService)(nil)

type JwtService interface {
	GenerateToken(ctx context.Context, p GenerateTokenParams) (*GenerateTokenResponse, error)
	ParseUnverified(ctx context.Context, p ParseUnverifiedParams) (*ParseUnverifiedResponse, error)
	Parse(ctx context.Context, p ParseParams) (*ParseResponse, error)
	Validate(ctx context.Context, p ValidateParams) (*ValidateResponse, error)
	Revoke(ctx context.Context, p RevokeParams) error
}

type jwtService struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	redis      redis.RedisService
}

type RevokeParams struct {
	TokenId string
	TTL     int
}

type ValidateParams struct {
	Token    string
	Expected map[string]interface{}
}

type ValidateResponse struct {
	IsValid bool
	Message string
}

type GenerateTokenParams struct {
	Claims map[string]interface{}
}

type GenerateTokenResponse struct {
	Token string
}

type ParseParams struct {
	Token     string
	TokenType TokenType
}

type ParseResponse struct {
	Claims map[string]interface{}
}

type ParseUnverifiedParams struct {
	Token string
}

type ParseUnverifiedResponse struct {
	Claims map[string]interface{}
}

type NewJwtServiceParams struct {
	Redis                redis.RedisService
	PublicKey            string
	PrivateKey           string
	PrivateKeyPassphrase string
}

func NewJwtService(p NewJwtServiceParams) JwtService {

	publicKey, err := go_jwt.ParseRSAPublicKeyFromPEM([]byte(p.PublicKey))
	if err != nil {
		log.Errorf("[JWT][NewJwtService] error parse public key: %v", err)
		panic(err)
	}

	privateKey := &rsa.PrivateKey{}
	if p.PrivateKeyPassphrase != "" {
		privateKey, err = go_jwt.ParseRSAPrivateKeyFromPEMWithPassword([]byte(p.PrivateKey), p.PrivateKeyPassphrase)
		if err != nil {
			log.Errorf("[JWT][NewJwtService] error parse private key with passphrase: %v", err)
			panic(err)
		}
	} else {
		privateKey, err = go_jwt.ParseRSAPrivateKeyFromPEM([]byte(p.PrivateKey))
		if err != nil {
			log.Errorf("[JWT][NewJwtService] error parse private key: %v", err)
			panic(err)
		}
	}

	return &jwtService{
		publicKey:  publicKey,
		privateKey: privateKey,
		redis:      p.Redis,
	}
}

func (s *jwtService) GenerateToken(ctx context.Context, p GenerateTokenParams) (*GenerateTokenResponse, error) {
	claims := go_jwt.MapClaims{}

	for key, value := range p.Claims {
		claims[key] = value
	}

	token := go_jwt.NewWithClaims(go_jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		log.Errorf("[JWT][GenerateAuthId] error signing token: %v", err)
		return nil, err
	}

	return &GenerateTokenResponse{
		Token: tokenString,
	}, nil
}

func (s *jwtService) Parse(ctx context.Context, p ParseParams) (*ParseResponse, error) {
	token, err := go_jwt.Parse(p.Token, func(token *go_jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*go_jwt.SigningMethodRSA); !ok {
			log.Errorf("[JWT][Parse] unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		log.Errorf("[JWT][Parse] token parse error: %v", err)
		return nil, errors.New("token parse error: " + err.Error())
	}

	if !token.Valid {
		log.Errorf("[JWT][Parse] invalid token")
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(go_jwt.MapClaims)
	if !ok {
		log.Errorf("[JWT][Parse] error parse claims")
		return nil, errors.New("error parse claims")
	}

	return &ParseResponse{
		Claims: claims,
	}, nil
}

func (s *jwtService) ParseUnverified(ctx context.Context, p ParseUnverifiedParams) (*ParseUnverifiedResponse, error) {
	parser := go_jwt.Parser{}

	token, _, err := parser.ParseUnverified(p.Token, go_jwt.MapClaims{})
	if err != nil {
		log.Errorf("[JWT][ParseUnverified] error parse token: %v", err)
		return nil, err
	}

	claims, ok := token.Claims.(go_jwt.MapClaims)
	if !ok {
		log.Errorf("[JWT][ParseUnverified] error parse claims")
		return nil, errors.New("error parse claims")
	}

	return &ParseUnverifiedResponse{
		Claims: claims,
	}, nil
}

func (s *jwtService) Validate(ctx context.Context, p ValidateParams) (*ValidateResponse, error) {
	res, err := s.Parse(ctx, ParseParams{
		Token: p.Token,
	})

	if err != nil {
		log.Errorf("[JWT][Validate] error parse token: %v", err)
		return nil, err
	}

	if _, ok := res.Claims["jti"]; !ok {
		log.Error("[JWT][Validate] jti not found")
		return nil, fmt.Errorf("jti not found")
	}

	isRevoked, err := s.redis.Exists(ctx, fmt.Sprintf(REVOKED_TOKEN_KEY, res.Claims["jti"].(string)))
	if err != nil {
		log.Errorf("[JWT][Validate] error check revoked token: %v", err)
		return nil, err
	}

	if isRevoked {
		return &ValidateResponse{
			IsValid: false,
			Message: "token revoked",
		}, nil
	}

	if _, ok := res.Claims["exp"]; !ok {
		log.Error("[JWT][Validate] exp not found")
		return nil, fmt.Errorf("exp not found")
	}

	if int64(res.Claims["exp"].(float64)) < p.Expected["exp"].(int64) {
		return &ValidateResponse{
			IsValid: false,
			Message: "token expired",
		}, nil
	}

	delete(p.Expected, "exp")

	if _, ok := res.Claims["iss"]; !ok {
		log.Error("[JWT][Validate] iss not found")
		return nil, fmt.Errorf("iss not found")
	}

	if res.Claims["iss"].(string) != p.Expected["iss"].(string) {
		return &ValidateResponse{
			IsValid: false,
			Message: "invalid issuer",
		}, nil
	}

	delete(p.Expected, "iss")

	if _, ok := res.Claims["aud"]; !ok {
		log.Error("[JWT][Validate] aud not found")
		return nil, fmt.Errorf("aud not found")
	}

	if res.Claims["aud"].(string) != p.Expected["aud"].(string) {
		return &ValidateResponse{
			IsValid: false,
			Message: "invalid audience",
		}, nil
	}

	delete(p.Expected, "aud")

	if _, ok := res.Claims["nbf"]; !ok {
		log.Error("[JWT][Validate] nbf not found")
		return nil, fmt.Errorf("nbf not found")
	}

	if int64(res.Claims["nbf"].(float64)) > p.Expected["nbf"].(int64) {
		return &ValidateResponse{
			IsValid: false,
			Message: "token not yet valid",
		}, nil
	}

	delete(p.Expected, "nbf")

	if _, ok := res.Claims["iat"]; !ok {
		log.Error("[JWT][Validate] iat not found")
		return nil, fmt.Errorf("iat not found")
	}

	if int64(res.Claims["iat"].(float64)) > p.Expected["iat"].(int64) {
		return &ValidateResponse{
			IsValid: false,
			Message: "token issued in the future",
		}, nil
	}

	delete(p.Expected, "iat")

	if _, ok := p.Expected["sub"]; ok {
		if _, ok := res.Claims["sub"]; !ok {
			log.Error("[JWT][Validate] sub not found")
			return nil, fmt.Errorf("sub not found")
		}

		if res.Claims["sub"].(string) != p.Expected["sub"].(string) {
			return &ValidateResponse{
				IsValid: false,
				Message: "invalid subject",
			}, nil
		}

		delete(p.Expected, "sub")
	}

	for key, value := range p.Expected {
		if _, ok := res.Claims[key]; !ok {
			log.Errorf("[JWT][Validate] %s not found", key)
			return nil, fmt.Errorf("%s not found", key)
		}

		if res.Claims[key] != value {
			return &ValidateResponse{
				IsValid: false,
				Message: fmt.Sprintf("invalid %s", key),
			}, nil
		}
	}

	return &ValidateResponse{
		IsValid: true,
		Message: "valid token",
	}, nil
}

func (s *jwtService) Revoke(ctx context.Context, p RevokeParams) error {
	err := s.redis.SetCacheWithExpiration(ctx, fmt.Sprintf(REVOKED_TOKEN_KEY, p.TokenId), "1", p.TTL)
	if err != nil {
		log.Errorf("[JWT][Revoke] error set cache: %v", err)
		return err
	}

	return nil
}
