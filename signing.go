package keymanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// SignPayload signs the payload using the provided private key. Supports ECDSA (P-256) and RSA-2048.
func SignPayload(priv interface{}, payload []byte) ([]byte, error) {
	h := sha256.Sum256(payload)
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		return ecdsaRSStoRaw(r, s, 32), nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			return nil, err
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

// ecdsaRSStoRaw converts r and s into the raw fixed-length concatenation (r||s).
func ecdsaRSStoRaw(r, s *big.Int, keyBytes int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, keyBytes*2)
	copy(sig[keyBytes-len(rb):keyBytes], rb)
	copy(sig[2*keyBytes-len(sb):], sb)
	return sig
}

// ECDSADERToRaw converts an ASN.1 DER ECDSA signature to raw r||s form with fixed length.
func ECDSADERToRaw(der []byte, keyBytes int) ([]byte, error) {
	var esig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &esig); err != nil {
		return nil, err
	}
	return ecdsaRSStoRaw(esig.R, esig.S, keyBytes), nil
}
