# JWT Library in Go

This is a simple Go library for working with JSON Web Tokens (JWTs). It supports generating JWTs with standard claims and private claims using the HMACSHA256 algorithm for signing.

## Prerequisites

Make sure you have Go installed on your machine. You can download it from [https://golang.org/dl/](https://golang.org/dl/).

## Installation

Clone the repository:

```bash
git clone https://github.com/skartikey/jwt-go.git
```

Change into the project directory:

```bash
cd jwt-go
```

## Running Tests

To run the unit tests for the JWT library, use the following command:

```bash
go test ./...
```

To run the benchmark tests, use the following command:

```bash
go test -bench=.
```

## Example Usage

You can use the JWT library in your Go code as follows:

```go
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
```

Remember to replace "your_secret_key" with your actual secret key.

## Benchmarks

The benchmark tests can be run using the following command:

```bash
go test -bench=.
```