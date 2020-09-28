package util

import (
	"crypto/rsa"
	"github.com/ma314smith/signedxml"
)

func Sign(a string, k *rsa.PrivateKey) (string, error) {
	signer, err := signedxml.NewSigner(a)
	if err != nil {
		return "", err
	}
	signedXML, err := signer.Sign(k)
	if err != nil {
		return "", err
	}
	return signedXML, nil
}
