package crypt

import (
	"crypto/aes"
	go_cipher "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	b64 "encoding/base64"

	"crypto/md5"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"

	log "github.com/sirupsen/logrus"
)

var _ CryptService = (*crypt)(nil)

const (
	HASHED_PASSWORD_FORMAT = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

type CryptService interface {
	// Hash is a function to hash data using sha256
	Hash(data string) string

	// Base64Encode is a function to encode data using base64
	Base64Encode(data string) string

	// Base64Decode is a function to decode data using base64
	Base64Decode(data string) (string, error)

	// Decrypt is a function to decrypt data using aes256-gcm
	Decrypt(key string, data string) (string, error)

	// Encrypt is a function to encrypt data using aes256-gcm
	Encrypt(key string, data string) (string, error)

	// PasswordHash is a function to hash password using argon2id
	PasswordHash(password string) (string, error)

	// PasswordVerify is a function to verify password using argon2id
	PasswordVerify(password string, hash string) (bool, error)

	// MD5 is a function to hash data using md5
	MD5(data string) (string, error)
}

type argon2idParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

type crypt struct {
	argon2idParams argon2idParams
}

func NewCrypt() CryptService {
	return &crypt{
		argon2idParams: argon2idParams{
			memory:      64 * 1024,
			iterations:  3,
			parallelism: 2,
			saltLength:  16,
			keyLength:   32,
		},
	}
}

// Hash is a function to hash data using sha256
func (c *crypt) Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := string(h.Sum(nil))
	return hashed
}

// Base64Encode is a function to encode data using base64
func (c *crypt) Base64Encode(data string) string {
	str := b64.URLEncoding.EncodeToString([]byte(data))
	return str
}

// Base64Decode is a function to decode data using base64
func (c *crypt) Base64Decode(data string) (string, error) {
	res, err := b64.URLEncoding.DecodeString(data)
	if err != nil {
		log.Errorf("[Crypt][Base64Decode] error decode base64: %v", err)
		return "", err
	}

	return string(res), nil
}

// Decrypt is a function to decrypt data using aes256-gcm
func (c *crypt) Decrypt(key string, data string) (string, error) {
	keyByte := []byte(key)
	dataByte := []byte(data)

	cipher, err := aes.NewCipher(keyByte)
	if err != nil {
		log.Errorf("[Crypt][Encrypt] error create cipher: %v", err)
		return "", err
	}

	gcm, err := go_cipher.NewGCM(cipher)
	if err != nil {
		log.Errorf("[Crypt][Encrypt] error create gcm: %v", err)
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(dataByte) < nonceSize {
		log.Errorf("[Crypt][Encrypt] error data length less than nonce size")
		return "", fmt.Errorf("error data length less than nonce size")
	}

	nonce, ciphertext := dataByte[:nonceSize], dataByte[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		log.Errorf("[Crypt][Encrypt] error decrypt: %v", err)
		return "", err
	}

	return string(plaintext), nil
}

// Encrypt is a function to encrypt data using aes256-gcm
func (c *crypt) Encrypt(key string, data string) (string, error) {
	dataByte := []byte(data)
	keyByte := []byte(key)

	cipher, err := aes.NewCipher(keyByte)
	if err != nil {
		log.Errorf("[Crypt][Encrypt] error create cipher: %v", err)
		return "", err
	}

	gcm, err := go_cipher.NewGCM(cipher)
	if err != nil {
		log.Errorf("[Crypt][Encrypt] error create gcm: %v", err)
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Errorf("[Crypt][Encrypt] error create nonce: %v", err)
		return "", err
	}

	encoded := gcm.Seal(nonce, nonce, dataByte, nil)
	cipherText := b64.URLEncoding.EncodeToString(encoded)

	return cipherText, nil
}

// PasswordHash is a function to hash password using argon2id
func (c *crypt) PasswordHash(password string) (string, error) {
	salt := make([]byte, c.argon2idParams.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		log.Errorf("[Crypt][PasswordHash] error generate salt: %v", err)
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, c.argon2idParams.iterations, c.argon2idParams.memory, c.argon2idParams.parallelism, c.argon2idParams.keyLength)

	b64Salt := b64.RawStdEncoding.EncodeToString(salt)
	b64Hash := b64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(HASHED_PASSWORD_FORMAT, argon2.Version, c.argon2idParams.memory, c.argon2idParams.iterations, c.argon2idParams.parallelism, b64Salt, b64Hash)

	base64EncodedHash := b64.RawStdEncoding.EncodeToString([]byte(encodedHash))

	return base64EncodedHash, nil
}

// PasswordVerify is a function to verify password using argon2id
func (c *crypt) PasswordVerify(password string, hash string) (bool, error) {

	decodedHash, err := b64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		log.Errorf("[Crypt][PasswordVerify] error decode hash: %v", err)
		return false, err
	}

	vals := strings.Split(string(decodedHash), "$")
	if len(vals) != 6 {
		log.Errorf("[Crypt][PasswordVerify] invalid hash format")
		return false, fmt.Errorf("invalid hash format")
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		log.Errorf("[Crypt][PasswordVerify] error parse version: %v", err)
		return false, err
	}

	if version != argon2.Version {
		log.Errorf("[Crypt][PasswordVerify] incompatible version of argon2")
		return false, fmt.Errorf("incompatible version of argon2")
	}

	p := &argon2idParams{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		log.Errorf("[Crypt][PasswordVerify] error parse params: %v", err)
		return false, err
	}

	salt, err := b64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		log.Errorf("[Crypt][PasswordVerify] error decode salt: %v", err)
		return false, err
	}
	// p.saltLength = uint32(len(salt))

	hashedPwd, err := b64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return false, err
	}
	p.keyLength = uint32(len(hashedPwd))

	hashedInput := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if subtle.ConstantTimeCompare(hashedPwd, hashedInput) == 1 {
		return true, nil
	}

	return false, nil
}

// MD5 is a function to hash data using md5
func (c *crypt) MD5(data string) (string, error) {

	h := md5.New()
	_, err := h.Write([]byte(data))
	if err != nil {
		log.Errorf("[Crypt][MD5] error write data: %v", err)
		return "", err
	}

	hashed := h.Sum(nil)

	return fmt.Sprintf("%x", hashed), nil
}
