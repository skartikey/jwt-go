package signature

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256SignatureGenerator implements the SignatureGenerator interface using HMAC-SHA256.
type HMACSHA256SignatureGenerator struct {
	Secret string
}

// NewHMACSHA256SignatureGenerator creates a new instance of HMACSHA256SignatureGenerator.
func NewHMACSHA256SignatureGenerator(secret string) *HMACSHA256SignatureGenerator {
	return &HMACSHA256SignatureGenerator{Secret: secret}
}

// Generate generates the HMACSHA256 signature for the given input.
func (g *HMACSHA256SignatureGenerator) Generate(data string) string {
	key := []byte(g.Secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return EncodeSegment(h.Sum(nil))
}
