package factory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

func GetClusterSecret(ctx context.Context, rc client.Client, c *opensearchv1alpha1.Cluster, postfix string) (*corev1.Secret, error) {
	n := GetNamespacedName(c)
	n.Name += "-" + postfix
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
	if err := rc.Get(ctx, n, s); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get secret with certificates: %w", err)
		}

		if err = rc.Create(ctx, s); err != nil {
			return nil, fmt.Errorf("failed to create empty secret object: %w", err)
		}
	}

	s.Labels = GetLabels(c, c.GetName())

	if err := controllerutil.SetOwnerReference(c, s, rc.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	return s, nil
}

func GenClusterConfigs(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster) error {
	s, err := GetClusterSecret(ctx, rc, c, "securityconfigs")
	if err != nil {
		return fmt.Errorf("failed to get cluster secret object: %w", err)
	}

	if content := c.GetSecurityConfig().GetConfig(); content != nil {
		s.Data["config.yml"] = []byte(*content)
	}

	if content := c.GetSecurityConfig().GetActionGroups(); content != nil {
		s.Data["action_groups.yml"] = []byte(*content)
	}

	if content := c.GetSecurityConfig().GetInternalUsers(); content != nil {
		s.Data["internal_users.yml"] = []byte(*content)
	}

	if content := c.GetSecurityConfig().GetRoles(); content != nil {
		s.Data["roles.yml"] = []byte(*content)
	}

	if content := c.GetSecurityConfig().GetRolesMapping(); content != nil {
		s.Data["roles_mapping.yml"] = []byte(*content)
	}

	if content := c.GetSecurityConfig().GetTenants(); content != nil {
		s.Data["tenants.yml"] = []byte(*content)
	}

	if err := rc.Update(ctx, s); err != nil {
		return fmt.Errorf("failed to update secret with securityconfigs: %w", err)
	}

	return nil

}

func GenClusterCerts(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster) error {
	s, err := GetClusterSecret(ctx, rc, c, "certificates")
	if err != nil {
		return fmt.Errorf("failed to get clsuter secret object: %w", err)
	}

	pem := c.GetConfig().GetPlugins().GetSecurity().GetSSL().GetTransport()
	if err = GetCaCertAndKeyPEM(s, pem); err != nil {
		return fmt.Errorf("failed to generate CA cert or key: %w", err)
	}

	if s.Data["admin.pem"], s.Data["admin-key.pem"], err = GetCertAndKeyPEM(s, pem, "ADMIN"); err != nil {
		return fmt.Errorf("failed to generate admin cert or key: %w", err)
	}

	if s.Data["client.pem"], s.Data["client-key.pem"], err = GetCertAndKeyPEM(s, pem, "CLIENT"); err != nil {
		return fmt.Errorf("failed to generate client cert or key: %w", err)
	}

	if err := rc.Update(ctx, s); err != nil {
		return fmt.Errorf("failed to update secret with certificates: %w", err)
	}

	return nil
}

func GetCertAndKeyPEM(s *corev1.Secret, c *opensearchv1alpha1.PrivacyEnhancedMailFormatSpec, cn string, sans ...string) ([]byte, []byte, error) {
	var privKeyPEM []byte
	var ok bool
	var err error

	if privKeyPEM, ok = s.Data[fmt.Sprintf("%s.key", strings.ToLower(cn))]; !ok {
		if privKeyPEM, err = GenPrivKeyPEM(); err != nil {
			return nil, nil, err
		}
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
	caCert, _ := x509.ParseCertificate(caCertDecoded.Bytes)

	cert := c.GetCertificate(false)
	for _, san := range sans {
		cert.AddSAN(san)
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

	cert := c.GetCertificate(true)
	caCertPEM, err := GenCaCertPEM(cert.GetX509(), caPrivKeyPEM)
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
