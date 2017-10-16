package api_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"fmt"

	"github.com/tomogoma/go-api-guard"
	"github.com/tomogoma/go-typed-errors"
)

type APIKeyMock struct {
	Val []byte
}

func (k APIKeyMock) Value() []byte {
	return k.Val
}

type DBMock struct {
	typederrs.NotFoundErrCheck

	ExpInsAPIKErr        error
	ExpAPIKBUsrIDVal     api.Key
	ExpAPIKsBUsrIDValErr error
	RecInsAPIKUsrID      string
}

func (db *DBMock) APIKeyByUserIDVal(userID string, key []byte) (api.Key, error) {
	if db.ExpAPIKsBUsrIDValErr != nil {
		return nil, db.ExpAPIKsBUsrIDValErr
	}
	if db.ExpAPIKBUsrIDVal == nil {
		return nil, typederrs.NewNotFound("not found")
	}
	return db.ExpAPIKBUsrIDVal, db.ExpAPIKsBUsrIDValErr
}

func (db *DBMock) InsertAPIKey(userID string, key []byte) (api.Key, error) {
	if db.ExpInsAPIKErr != nil {
		return nil, db.ExpInsAPIKErr
	}
	db.RecInsAPIKUsrID = userID
	return APIKeyMock{Val: key}, db.ExpInsAPIKErr
}

type KeyGenMock struct {
	ExpSRBsErr error
	ExpSRBs    []byte
}

func (kg *KeyGenMock) SecureRandomBytes(length int) ([]byte, error) {
	if kg.ExpSRBsErr != nil {
		return nil, kg.ExpSRBsErr
	}
	return kg.ExpSRBs, kg.ExpSRBsErr
}

func ExampleGuard() {

	db := &DBMock{}
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
}

func TestNewGuard(t *testing.T) {
	tt := []struct {
		name   string
		db     api.KeyStore
		opts   []api.Option
		expErr bool
	}{
		{
			name:   "valid no opts",
			db:     &DBMock{},
			expErr: false,
		},
		{
			name:   "valid w valid master key",
			db:     &DBMock{},
			opts:   []api.Option{api.WithMasterKey("master-key")},
			expErr: false,
		},
		{
			name:   "valid w valid key gen",
			db:     &DBMock{},
			opts:   []api.Option{api.WithKeyGenerator(&KeyGenMock{})},
			expErr: false,
		},
		{
			name:   "valid w valid API Key len",
			db:     &DBMock{},
			opts:   []api.Option{api.WithAPIKeyLen(4)}, // 4 is the minimum
			expErr: false,
		},
		{
			name:   "nil db",
			db:     nil,
			expErr: true,
		},
		{
			name:   "nil key gen",
			db:     &DBMock{},
			opts:   []api.Option{api.WithKeyGenerator(nil)},
			expErr: true,
		},
		{
			name:   "bad API Key len",
			db:     &DBMock{},
			opts:   []api.Option{api.WithAPIKeyLen(3)}, // 4 is the minimum
			expErr: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			g, err := api.NewGuard(tc.db, tc.opts...)
			if tc.expErr {
				if err == nil {
					t.Fatalf("Expected error got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("api.NewGuard(): %v", err)
			}
			if g == nil {
				t.Fatalf("api.NewGuard returned nil *api.Guard")
			}
		})
	}
}

func TestGuard_NewAPIKey(t *testing.T) {
	validKey := "some-api-key"
	userID := "123456"
	userIDB64 := base64.StdEncoding.EncodeToString([]byte(userID))
	tt := []struct {
		name     string
		userID   string
		db       *DBMock
		opts     []api.Option
		expKey   []byte
		expErr   bool
		expClErr bool
	}{
		{
			name:   "valid",
			userID: userID,
			opts:   []api.Option{api.WithKeyGenerator(&KeyGenMock{ExpSRBs: []byte(validKey)})},
			db:     &DBMock{},
			expKey: []byte(userIDB64 + "." + validKey),
			expErr: false,
		},
		{
			name:     "missing userID",
			userID:   "",
			opts:     []api.Option{api.WithKeyGenerator(&KeyGenMock{ExpSRBs: []byte(validKey)})},
			db:       &DBMock{},
			expErr:   true,
			expClErr: true,
		},
		{
			name:   "key gen report error",
			userID: userID,
			opts:   []api.Option{api.WithKeyGenerator(&KeyGenMock{ExpSRBsErr: typederrs.Newf("an error")})},
			db:     &DBMock{},
			expErr: true,
		},
		{
			name:   "db report error",
			userID: userID,
			opts:   []api.Option{api.WithKeyGenerator(&KeyGenMock{ExpSRBs: []byte(validKey)})},
			db:     &DBMock{ExpInsAPIKErr: typederrs.Newf("whoops, an error")},
			expErr: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuard(t, tc.db, tc.opts...)
			ak, err := g.NewAPIKey(tc.userID)
			if tc.expErr {
				if err == nil {
					t.Fatalf("Error: %v", err)
				}
				if tc.expClErr != g.IsClientError(err) {
					t.Errorf("Expect api.Guard#IsClientError %t, got %t",
						tc.expClErr, g.IsClientError(err))
				}
				return
			}
			if ak == nil {
				t.Fatalf("yielded nil *api.Key")
			}
			if !bytes.Equal(ak.Value(), tc.expKey) {
				t.Errorf("API Key mismatch: expect '%s' got '%s'",
					tc.expKey, ak.Value)
			}
			if tc.userID != tc.db.RecInsAPIKUsrID {
				t.Errorf("User ID mismatch: expect '%s', got '%s'",
					tc.userID, tc.db.RecInsAPIKUsrID)
			}
		})
	}
}

func TestGuard_APIKeyValid(t *testing.T) {
	guard := newGuard(t, &DBMock{})
	validUsrID := "12.34"
	validKey, err := guard.NewAPIKey(validUsrID)
	if err != nil {
		t.Fatalf("Error setting up: generate API Key: %v", err)
	}
	masterKey := "the-master-key"
	tt := []struct {
		name            string
		key             []byte
		expUsrID        string
		db              *DBMock
		opts            []api.Option
		expErr          bool
		expForbidden    bool
		expUnauthorized bool
	}{
		{
			name:     "valid (db)",
			expUsrID: validUsrID,
			key:      validKey.Value(),
			db:       &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:   false,
		},
		{
			name:     "valid (master)",
			key:      []byte(masterKey),
			opts:     []api.Option{api.WithMasterKey(masterKey)},
			expUsrID: api.MasterUser,
			db:       &DBMock{ExpAPIKsBUsrIDValErr: typederrs.NewNotFound("")},
			expErr:   false,
		},
		{
			name:            "empty",
			key:             make([]byte, 0),
			expUsrID:        "",
			db:              &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:          true,
			expForbidden:    false,
			expUnauthorized: true,
		},
		{
			name:            "separator only",
			key:             []byte("."),
			expUsrID:        "",
			db:              &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:          true,
			expForbidden:    false,
			expUnauthorized: true,
		},
		{
			name:            "missing separator (key)",
			key:             bytes.SplitN(validKey.Value(), []byte("."), 2)[1],
			expUsrID:        "",
			db:              &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:          true,
			expForbidden:    false,
			expUnauthorized: true,
		},
		{
			name:            "missing separator (b64 userID)",
			key:             bytes.SplitN(validKey.Value(), []byte("."), 2)[0],
			expUsrID:        "",
			db:              &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:          true,
			expForbidden:    false,
			expUnauthorized: true,
		},
		{
			name: "invalid key",
			// "aW52YWxpZFVzZXJJRA==" => base64("invalidUserID")
			key:             []byte("aW52YWxpZFVzZXJJRA==.anapikey"),
			expUsrID:        "invalidUserID",
			db:              &DBMock{ExpAPIKBUsrIDVal: validKey},
			expErr:          true,
			expForbidden:    true,
			expUnauthorized: false,
		},
		{
			name:            "none found",
			key:             validKey.Value(),
			expUsrID:        validUsrID,
			db:              &DBMock{ExpAPIKsBUsrIDValErr: typederrs.NewNotFound("no keys for 12345")},
			expErr:          true,
			expForbidden:    true,
			expUnauthorized: false,
		},
		{
			name:     "db report error",
			key:      validKey.Value(),
			expUsrID: validUsrID,
			db:       &DBMock{ExpAPIKsBUsrIDValErr: typederrs.New("some errors")},
			expErr:   true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuard(t, tc.db, tc.opts...)
			usrID, err := g.APIKeyValid(tc.key)
			if usrID != tc.expUsrID {
				t.Errorf("Expected userID '%s', got '%s'", tc.expUsrID, usrID)
			}
			if tc.expErr {
				if err == nil {
					t.Fatalf("Expected an error, got nil")
				}
				if tc.expUnauthorized != g.IsUnauthorizedError(err) {
					t.Errorf("Expect api.Guard#IsUnauthorizedError %t, got %t: %v",
						tc.expUnauthorized, g.IsUnauthorizedError(err), err)
				}
				if tc.expForbidden != g.IsForbiddenError(err) {
					t.Errorf("Expect api.Guard#IsForbiddenError %t, got %t: %v",
						tc.expForbidden, g.IsForbiddenError(err), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected nil error, got %v", err)
			}
		})
	}
}

func newGuard(t *testing.T, db api.KeyStore, opts ...api.Option) *api.Guard {
	g, err := api.NewGuard(db, opts...)
	if err != nil {
		t.Fatalf("Error setting up apiguard.NewGuard(): %v", err)
	}
	return g
}
