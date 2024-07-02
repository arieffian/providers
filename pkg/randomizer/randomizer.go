package randomizer

import (
	"bytes"
	"math/rand"

	"github.com/google/uuid"
)

const (
	UPPERCASE_ALPHABETS = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
	LOWERCASE_ALPHABETS = `abcdefghijklmnopqrstuvwxyz`
	NUMBERS             = `123456789`
	SPECIAL_CHARACTERS  = `!@#$%^&*()`
	SPACE               = ` `
)

var _ RandomizerService = (*randomizer)(nil)

type RandomizerService interface {
	GenerateRandomString(p GenerateRandomStringParam) string
	GenerateUUID() string
}

type randomizer struct{}

type GenerateRandomStringParam struct {
	Length             int
	UppercaseAlphabets bool
	LowercaseAlphabets bool
	Numbers            bool
	SpecialCharacters  bool
	Space              bool
}

func (r *randomizer) GenerateRandomString(p GenerateRandomStringParam) string {
	if p.Length <= 0 {
		return ""
	}
	poolBuff := bytes.Buffer{}
	if p.UppercaseAlphabets {
		poolBuff.WriteString(UPPERCASE_ALPHABETS)
	}
	if p.LowercaseAlphabets {
		poolBuff.WriteString(LOWERCASE_ALPHABETS)
	}
	if p.Numbers {
		poolBuff.WriteString(NUMBERS)
	}
	if p.SpecialCharacters {
		poolBuff.WriteString(SPECIAL_CHARACTERS)
	}
	if p.Space {
		poolBuff.WriteString(SPACE)
	}
	bpool := poolBuff.Bytes()
	buff := bytes.Buffer{}
	for buff.Len() < p.Length {
		buff.WriteByte(bpool[rand.Intn(len(bpool))])
	}
	return buff.String()
}

func (r *randomizer) GenerateUUID() string {
	return uuid.NewString()
}

func NewRandomizer() *randomizer {
	return &randomizer{}
}
