package keymanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

func base64URLNoPadEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// jwkFromPublicKey returns a JWK map for the given public key.
func jwkFromPublicKey(kid string, pub interface{}, alg string) (map[string]interface{}, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		x := base64URLNoPadEncode(p.X.Bytes())
		y := base64URLNoPadEncode(p.Y.Bytes())
		if alg == "" {
			alg = "ES256"
		}
		return map[string]interface{}{"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": alg, "x": x, "y": y}, nil
	case *rsa.PublicKey:
		n := base64URLNoPadEncode(p.N.Bytes())
		e := base64URLNoPadEncode(big.NewInt(int64(p.E)).Bytes())
		if alg == "" {
			alg = "RS256"
		}
		return map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": alg, "n": n, "e": e}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// jwkFromPrivateKey extracts the public key and returns a JWK
func jwkFromPrivateKey(kid string, priv interface{}, alg string) (map[string]interface{}, error) {
	switch p := priv.(type) {
	case *ecdsa.PrivateKey:
		return jwkFromPublicKey(kid, &p.PublicKey, alg)
	case *rsa.PrivateKey:
		return jwkFromPublicKey(kid, &p.PublicKey, alg)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// JWKSFromPrivateKeyMap builds a JWKS from a map of kid->privateKey
func JWKSFromPrivateKeyMap(keys map[string]interface{}) (map[string]interface{}, error) {
	out := []interface{}{}
	for kid, v := range keys {
		if jwk, err := jwkFromPrivateKey(kid, v, ""); err == nil {
			out = append(out, jwk)
		}
	}
	return map[string]interface{}{"keys": out}, nil
}
