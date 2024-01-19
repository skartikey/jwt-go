package jwt

import (
	"encoding/json"
	"time"

	"github.com/skartikey/jwt-go/pkg/signature"
)

// Claims represents the standard JWT claims.
type Claims struct {
	Iss string                 `json:"iss"`
	Sub string                 `json:"sub"`
	Aud string                 `json:"aud"`
	Iat int64                  `json:"iat"`
	Nam string                 `json:"nam"`
	Pri map[string]interface{} `json:"pri,omitempty"`
}

// JWT represents the structure of a JSON Web Token.
type JWT struct {
	Header          map[string]string
	Claims          Claims
	SignatureMethod signature.Generator
}

// NewJWT initializes a new JWT with default values.
func NewJWT(issuer, subject, audience, name string, signatureGenerator signature.Generator) *JWT {
	return &JWT{
		Header: map[string]string{"alg": "HS256", "typ": "JWT"},
		Claims: Claims{
			Iss: issuer,
			Sub: subject,
			Aud: audience,
			Iat: time.Now().Unix(),
			Nam: name,
			Pri: make(map[string]interface{}),
		},
		SignatureMethod: signatureGenerator,
	}
}

// AddPrivateClaim adds a private claim to the JWT.
func (jwt *JWT) AddPrivateClaim(key string, value interface{}) {
	jwt.Claims.Pri[key] = value
}

// GenerateToken generates a JWT token.
func (jwt *JWT) GenerateToken() (string, error) {
	headerJSON, err := json.Marshal(jwt.Header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(jwt.Claims)
	if err != nil {
		return "", err
	}

	encodedHeader := signature.EncodeSegment(headerJSON)
	encodedClaims := signature.EncodeSegment(claimsJSON)

	signatureInput := encodedHeader + "." + encodedClaims
	signature := jwt.GenerateSignature(signatureInput)

	return signatureInput + "." + signature, nil
}

// GenerateSignature generates the JWT signature using the configured SignatureGenerator.
func (jwt *JWT) GenerateSignature(data string) string {
	return jwt.SignatureMethod.Generate(data)
}
