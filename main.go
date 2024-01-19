package main

import (
	"fmt"

	"github.com/skartikey/jwt-go/pkg/jwt"
	"github.com/skartikey/jwt-go/pkg/signature"
)

func main() {
	// Set up JWT parameters
	issuer := "issuer"
	subject := "subject"
	audience := "audience"
	name := "John Doe"
	secretKey := "your_secret_key"

	// Initialize a new HMACSHA256SignatureGenerator
	signatureGenerator := signature.NewHMACSHA256SignatureGenerator(secretKey)

	// Initialize a new JWT with claims and the HMACSHA256SignatureGenerator
	jwtManager := jwt.NewJWT(issuer, subject, audience, name, signatureGenerator)

	// Add private claims if needed
	jwtManager.AddPrivateClaim("custom_key", "custom_value")

	// Generate JWT token
	token, err := jwtManager.GenerateToken()
	if err != nil {
		fmt.Println("Error generating JWT token:", err)
		return
	}

	fmt.Println("Generated JWT token:", token)
}
