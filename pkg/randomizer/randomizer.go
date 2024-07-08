package randomizer

import (
	"bytes"
	"math/big"

	"strings"

	"crypto/rand"
	"fmt"
	"time"

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
	GenerateTrxId(suffix string) string
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
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(bpool))))
		if err != nil {
			return ""
		}
		n := nBig.Int64()
		buff.WriteByte(bpool[n])
	}
	return buff.String()
}

func (r *randomizer) GenerateUUID() string {
	return uuid.NewString()
}

func (r *randomizer) GenerateTrxId(suffix string) string {
	t := time.Now()

	res := t.Format("20060102")

	h, m, s := t.Clock()
	ms := t.Nanosecond() / int(time.Millisecond)

	res += fmt.Sprintf("%02d%02d%02d%03d", h, m, s, ms)

	res += "-" + r.GenerateRandomString(GenerateRandomStringParam{
		Length:             8,
		UppercaseAlphabets: true,
		Numbers:            true,
	})

	suffix = strings.ToUpper(suffix)

	return suffix + res
}

func NewRandomizer() *randomizer {
	return &randomizer{}
}
