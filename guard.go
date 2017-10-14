// api provides a mechanism for managing and validating API keys.
package api

import (
	"bytes"
	"encoding/base64"
	"time"

	"github.com/tomogoma/generator"
	"github.com/tomogoma/go-typed-errors"
)

const (
	DefaultAPIKeyLength = 56
	MasterUser          = "master"
)

type KeyStore interface {
	IsNotFoundError(error) bool
	InsertAPIKey(userID string, key []byte) (*Key, error)
	APIKeysByUserID(userID string, offset, count int64) ([]Key, error)
}

type KeyGenerator interface {
	SecureRandomBytes(length int) ([]byte, error)
}

type Key struct {
	ID         string
	UserID     string
	Value      []byte
	CreateDate time.Time
	UpdateDate time.Time
}

type Guard struct {
	typederrs.ClErrCheck
	typederrs.AuthErrCheck
	db        KeyStore
	gen       KeyGenerator
	masterKey string
	apiKeyLen int
}

var badKeyWUsrErrf = "invalid API key (%s) for %s"
var badKeyErrf = "invalid API key (%s)"

func NewGuard(db KeyStore, opts ...Option) (*Guard, error) {
	if db == nil {
		return nil, typederrs.New("KeyStore was nil")
	}
	g := &Guard{db: db, apiKeyLen: DefaultAPIKeyLength}
	var err error
	g.gen, err = generator.NewCharSet(generator.AlphaNumericChars)
	if err != nil {
		return nil, typederrs.Newf("creating API Key generator")
	}
	for _, f := range opts {
		if err := f(g); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (s *Guard) APIKeyValid(key []byte) (string, error) {

	if len(key) != 0 && bytes.Equal(key, []byte(s.masterKey)) {
		return MasterUser, nil
	}

	pair := bytes.SplitN(key, []byte("."), 2)
	if len(pair) < 2 || len(pair[0]) == 0 {
		return "", typederrs.NewUnauthorizedf(badKeyErrf, key)
	}

	userIDB := make([]byte, len(pair[0]))
	n, err := base64.StdEncoding.Decode(userIDB, pair[0])
	if err != nil {
		return "", typederrs.NewForbiddenf(badKeyErrf, key)
	}
	userID := string(userIDB[:n])

	dbKeys, err := s.db.APIKeysByUserID(userID, 0, 10)
	if err != nil {
		if s.db.IsNotFoundError(err) {
			return userID, typederrs.NewForbiddenf(badKeyWUsrErrf, key, userID)
		}
		return userID, typederrs.Newf("get API Key: %v", err)
	}

	for _, dbKey := range dbKeys {
		if bytes.Equal(dbKey.Value, key) {
			return userID, nil
		}
	}

	return userID, typederrs.NewForbiddenf(badKeyWUsrErrf, key, userID)
}

func (s *Guard) NewAPIKey(userID string) (*Key, error) {

	if userID == "" {
		return nil, typederrs.NewClient("userID was empty")
	}
	userID = base64.StdEncoding.EncodeToString([]byte(userID))

	key, err := s.gen.SecureRandomBytes(s.apiKeyLen)
	if err != nil {
		return nil, typederrs.Newf("generate key: %v", err)
	}
	key = bytes.Join([][]byte{[]byte(userID), key}, []byte("."))

	k, err := s.db.InsertAPIKey(userID, key)
	if err != nil {
		return nil, typederrs.Newf("store key: %v", err)
	}
	return k, nil
}
