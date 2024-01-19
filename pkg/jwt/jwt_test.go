package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skartikey/jwt-go/pkg/jwt"
	"github.com/skartikey/jwt-go/pkg/signature"
)

func TestGenerateToken(t *testing.T) {
	// Set up test data
	issuer := "test_issuer"
	subject := "test_subject"
	audience := "test_audience"
	name := "Test User"
	secret := "test_secret"

	// Create a new JWT with HMACSHA256 signature generator
	signatureGenerator := signature.NewHMACSHA256SignatureGenerator(secret)
	jwtManager := jwt.NewJWT(issuer, subject, audience, name, signatureGenerator)

	// Add private claims
	jwtManager.AddPrivateClaim("custom_key", "custom_value")

	// Generate JWT token
	token, err := jwtManager.GenerateToken()
	if err != nil {
		t.Errorf("Error generating JWT token: %v", err)
	}

	// Split token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Invalid JWT token format: %s", token)
	}

	// Decode and verify header
	decodedHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Errorf("Error decoding JWT header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		t.Errorf("Error unmarshaling JWT header: %v", err)
	}

	// Verify algorithm
	if alg, ok := header["alg"]; !ok || alg != "HS256" {
		t.Errorf("Invalid JWT algorithm: %s", alg)
	}

	// Decode and verify claims
	decodedClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Errorf("Error decoding JWT claims: %v", err)
	}
	var claims jwt.Claims
	if err := json.Unmarshal(decodedClaims, &claims); err != nil {
		t.Errorf("Error unmarshaling JWT claims: %v", err)
	}

	// Verify standard claims
	if claims.Iss != issuer {
		t.Errorf("Invalid issuer: %s", claims.Iss)
	}
	if claims.Sub != subject {
		t.Errorf("Invalid subject: %s", claims.Sub)
	}
	if claims.Aud != audience {
		t.Errorf("Invalid audience: %s", claims.Aud)
	}
	if claims.Nam != name {
		t.Errorf("Invalid name: %s", claims.Nam)
	}
	if claims.Iat == 0 {
		t.Error("Invalid iat: 0")
	}

	// Verify custom claim
	if customValue, ok := claims.Pri["custom_key"]; !ok || customValue != "custom_value" {
		t.Errorf("Invalid custom claim: %v", claims.Pri)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	// Mock data
	issuer := "test_issuer"
	subject := "test_subject"
	audience := "test_audience"
	name := "John Doe"
	secret := "test_secret"

	// Create a new JWT with HMACSHA256 signature generator
	signatureGenerator := signature.NewHMACSHA256SignatureGenerator(secret)
	jwtManager := jwt.NewJWT(issuer, subject, audience, name, signatureGenerator)

	// Add private claim
	jwtManager.AddPrivateClaim("custom_key", "custom_value")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Benchmark the GenerateToken method
		_, err := jwtManager.GenerateToken()
		if err != nil {
			b.Errorf("Error generating token: %v", err)
		}
	}
}
