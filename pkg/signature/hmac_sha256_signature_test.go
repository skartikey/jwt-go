package signature_test

import (
	"crypto/sha256"
	"testing"

	"github.com/skartikey/jwt-go/pkg/signature"
)

func TestHMACSHA256SignatureGenerator_Generate(t *testing.T) {
	// Set up test data
	secret := "test_secret"
	data := "test_data"

	// Initialize a new HMACSHA256SignatureGenerator
	signatureGenerator := signature.NewHMACSHA256SignatureGenerator(secret)

	// Generate signature
	generatedSignature := signatureGenerator.Generate(data)

	// Decode and verify signature
	decodedSignature, err := signature.DecodeSegment(generatedSignature)
	if err != nil {
		t.Fatalf("Error decoding signature: %v", err)
	}

	// Verify the length of the decoded signature
	if len(decodedSignature) != sha256.Size {
		t.Errorf("Invalid signature length: %d", len(decodedSignature))
	}
}

func BenchmarkHMACSHA256SignatureGenerator_Generate(b *testing.B) {
	// Set up test data
	secret := "test_secret"
	data := "test_data"

	// Initialize a new HMACSHA256SignatureGenerator
	signatureGenerator := signature.NewHMACSHA256SignatureGenerator(secret)

	// Reset the benchmark timer
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		// Benchmark the Generate method
		_ = signatureGenerator.Generate(data)
	}
}
