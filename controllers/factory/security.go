package factory

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

func GetCertAndKeyPEM(s *corev1.Secret, c *opensearchv1alpha1.PrivacyEnhancedMailFormatSpec, cn string, sans ...string) ([]byte, []byte, error) {
	var privKeyPEM []byte
	var ok bool
	var err error

	if privKeyPEM, ok = s.Data[fmt.Sprintf("%s.key", strings.ToLower(cn))]; !ok {
		if privKeyPEM, err = GenPrivKeyPEM(); err != nil {
			return nil, nil, err
		}
	}

	if _, ok := s.Data["root-ca.pem"]; !ok {
		return nil, nil, fmt.Errorf("CA certs doesn't exists yet")
	}

	certPem, err := GenCertPEM(c, s.Data["root-ca.pem"], s.Data["root-ca-key.pem"], privKeyPEM, cn, sans...)
	if err != nil {
		return nil, nil, err
	}

	return certPem, privKeyPEM, nil
}

func GenCertPEM(c *opensearchv1alpha1.PrivacyEnhancedMailFormatSpec, ca, caPrivKeyPEM, privKeyPEM []byte, cn string, sans ...string) ([]byte, error) {
	caPrivKeyDecoded, _ := pem.Decode(caPrivKeyPEM)
	caPrivKey, err := x509.ParsePKCS1PrivateKey(caPrivKeyDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	privKeyDecoded, _ := pem.Decode(privKeyPEM)
	privKey, err := x509.ParsePKCS8PrivateKey(privKeyDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	var priv *rsa.PrivateKey
	var ok bool
	if priv, ok = privKey.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("admin priv key type accertion error")
	}

	caCertDecoded, _ := pem.Decode(ca)
	if caCertDecoded == nil || caCertDecoded.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse CA cert pem")
	}

	caCert, _ := x509.ParseCertificate(caCertDecoded.Bytes)

	cert := c.GetCertificate(false)
	for _, san := range sans {
		cert.AddSubjectAltName(san)
	}
	cert.AddCommonName(cn)

	b, err := x509.CreateCertificate(rand.Reader, cert.GetX509(), caCert, &priv.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	cb := new(bytes.Buffer)
	pem.Encode(cb, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})

	return cb.Bytes(), nil
}

func GenPrivKeyPEM() ([]byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gen admin key: %w", err)
	}

	adminPrivKeyBodyPEM, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	adminPrivKeyBufferPEM := new(bytes.Buffer)
	pem.Encode(adminPrivKeyBufferPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: adminPrivKeyBodyPEM,
	})

	return adminPrivKeyBufferPEM.Bytes(), nil
}

func GetCaCertAndKeyPEM(s *corev1.Secret, c *opensearchv1alpha1.PrivacyEnhancedMailFormatSpec) error {
	var caPrivKeyPEM []byte
	var ok bool
	var err error

	if caPrivKeyPEM, ok = s.Data["root-ca-key.pem"]; !ok {
		if caPrivKeyPEM, err = GenCaPrivKeyPEM(); err != nil {
			return err
		}
	}

	var cert *x509.Certificate
	var caCertPEM []byte
	if _, ok := s.Data["root-ca.pem"]; !ok {
		cert = c.GetCertificate(true).GetX509()
		caCertPEM, err = GenCaCertPEM(cert, caPrivKeyPEM)
	} else {
		caCertPEM = s.Data["root-ca.pem"]
		certBlock, _ := pem.Decode(s.Data["root-ca.pem"])
		if certBlock == nil || certBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode pem cert body")
		}

		cert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate der: %w", err)
		}

		if time.Now().After(cert.NotAfter) {
			caCertPEM, err = GenCaCertPEM(cert, caPrivKeyPEM)
		}
	}
	if err != nil {
		return fmt.Errorf("gen CA cert: %w", err)
	}

	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	s.Data["root-ca-key.pem"] = caPrivKeyPEM
	s.Data["root-ca.pem"] = caCertPEM

	return nil
}

func GenCaCertPEM(c *x509.Certificate, privKeyPEM []byte) ([]byte, error) {
	privKeyDecoded, _ := pem.Decode(privKeyPEM)
	priv, err := x509.ParsePKCS1PrivateKey(privKeyDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	b, err := x509.CreateCertificate(rand.Reader, c, c, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := new(bytes.Buffer)
	pem.Encode(cert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})

	return cert.Bytes(), nil
}

func GenCaPrivKeyPEM() ([]byte, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gen CA key: %w", err)
	}

	caPrivKeyBufferPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyBufferPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return caPrivKeyBufferPEM.Bytes(), nil
}
