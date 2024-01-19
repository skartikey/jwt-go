package signature

import (
	"encoding/base64"
	"fmt"
)

// Generator is an interface for generating JWT signatures.
type Generator interface {
	Generate(data string) string
}

// EncodeSegment encodes a byte slice to a Base64 URL-safe string.
func EncodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeSegment decodes a Base64 URL-safe string to a byte slice.
func DecodeSegment(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}
	return decoded, nil
}
