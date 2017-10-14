package api

import "github.com/tomogoma/go-commons/errors"

type Option func(*Guard) error

func WithMasterKey(key string) Option {
	return func(g *Guard) error {
		g.masterKey = key
		return nil
	}
}

func WithKeyGenerator(kg KeyGenerator) Option {
	return func(g *Guard) error {
		if kg == nil {
			return errors.Newf("KeyGenerator was nil")
		}
		g.gen = kg
		return nil
	}
}

func WithAPIKeyLen(l int) Option {
	return func(g *Guard) error {
		if l < 4 {
			return errors.Newf("API key length was too small")
		}
		g.apiKeyLen = l
		return nil
	}
}
