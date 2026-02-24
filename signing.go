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
	// zero DER input as it's sensitive
	for i := range der {
		der[i] = 0
	}
	return ecdsaRSStoRaw(esig.R, esig.S, keyBytes), nil
}

// zeroPrivateKey attempts to overwrite sensitive big.Int fields inside a
// private key structure to reduce the time secret material remains in memory.
func zeroPrivateKey(priv interface{}) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k.D != nil {
			k.D.SetInt64(0)
		}
		for i := range k.Primes {
			if k.Primes[i] != nil {
				k.Primes[i].SetInt64(0)
			}
		}
		// zero precomputed values
		if k.Precomputed.Dp != nil {
			k.Precomputed.Dp.SetInt64(0)
		}
		if k.Precomputed.Dq != nil {
			k.Precomputed.Dq.SetInt64(0)
		}
		if k.Precomputed.Qinv != nil {
			k.Precomputed.Qinv.SetInt64(0)
		}
		for i := range k.Precomputed.CRTValues {
			v := &k.Precomputed.CRTValues[i]
			if v.Exp != nil {
				v.Exp.SetInt64(0)
			}
			if v.Coeff != nil {
				v.Coeff.SetInt64(0)
			}
			if v.R != nil {
				v.R.SetInt64(0)
			}
		}
	case *ecdsa.PrivateKey:
		if k.D != nil {
			k.D.SetInt64(0)
		}
		if k.X != nil {
			k.X.SetInt64(0)
		}
		if k.Y != nil {
			k.Y.SetInt64(0)
		}
	default:
		// nothing we can do generically
	}
}
