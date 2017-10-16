# go-api-guard

a golang package that provides a mechanism for managing and validating API keys.

# Installation and docs

Install using `go get github.com/tomogoma/go-api-guard`

Godocs can be found at http://godoc.org/github.com/tomogoma/go-api-guard

# Typical Usage

```go

db := &DBMock{} //implements KeyStore interface

// mocking key generation to demonstrate resulting API key
keyGen := &KeyGenMock{ExpSRBs: []byte("an-api-key")}

g, _ := api.NewGuard(
    db,
    api.WithKeyGenerator(keyGen), // This is optional
)

// Generate API key
APIKey, _ := g.NewAPIKey("my-unique-user-id")

fmt.Println(string(APIKey.Value()))

// Validate API Key
userID, _ := g.APIKeyValid(APIKey.Value())

fmt.Println(userID)

// Output:
// bXktdW5pcXVlLXVzZXItaWQ=.an-api-key
// my-unique-user-id
```
