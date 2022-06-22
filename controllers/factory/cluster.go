package factory

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

func GenClusterConfigs(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster) error {
	s, err := GetClusterSecret(ctx, rc, c, "securityconfigs")
	if err != nil {
		return fmt.Errorf("failed to get cluster secret object: %w", err)
	}

	sc := c.GetSecurityConfig()
	if sc.Config != nil {
		s.Data["config.yml"] = []byte(*sc.Config)
	}

	if sc.ActionGroups != nil {
		s.Data["action_groups.yml"] = []byte(*sc.ActionGroups)
	}

	if sc.InternalUsers != nil {
		s.Data["internal_users.yml"] = []byte(*sc.InternalUsers)
	}

	if sc.Roles != nil {
		s.Data["roles.yml"] = []byte(*sc.Roles)
	}

	if sc.RolesMapping != nil {
		s.Data["roles_mapping.yml"] = []byte(*sc.RolesMapping)
	}

	if sc.Tenants != nil {
		s.Data["tenants.yml"] = []byte(*sc.Tenants)
	}

	if err = ReplaceSecret(ctx, rc, s); err != nil {
		return fmt.Errorf("failed to replace securityconfigs: %w", err)
	}

	return nil

}

func GenClusterCerts(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster) error {
	s, err := GetClusterSecret(ctx, rc, c, "certificates")
	if err != nil {
		return fmt.Errorf("failed to get clsuter secret object: %w", err)
	}

	pem := c.GetConfig().GetTransportLayerSSL()
	if s.Data["root-ca.pem"], s.Data["root-ca-key.pem"], err = GetCaCertAndKeyPEM(s, pem); err != nil {
		return fmt.Errorf("failed to generate CA cert or key: %w", err)
	}

	if s.Data["admin.pem"], s.Data["admin-key.pem"], err = GetCertAndKeyPEM(s, pem, "ADMIN"); err != nil {
		return fmt.Errorf("failed to generate admin cert or key: %w", err)
	}

	if s.Data["client.pem"], s.Data["client-key.pem"], err = GetCertAndKeyPEM(s, pem, "CLIENT"); err != nil {
		return fmt.Errorf("failed to generate client cert or key: %w", err)
	}

	if err = ReplaceSecret(ctx, rc, s); err != nil {
		return fmt.Errorf("failed to replace certificates: %w", err)
	}

	return nil
}

func GetClusterSecret(ctx context.Context, rc client.Client, c *opensearchv1alpha1.Cluster, postfix string) (*corev1.Secret, error) {
	n := c.GetSubresourceNamespacedName()
	n.Name = fmt.Sprintf("%s-%s", n.Name, postfix)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
	if err := rc.Get(ctx, n, s); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get cluster Secret object: %w", err)
		}

		if err = rc.Create(ctx, s); err != nil {
			return nil, fmt.Errorf("failed to create cluster Secret object: %w", err)
		}
	}

	s.Labels = c.GetSubresourceLabels()

	if err := controllerutil.SetOwnerReference(c, s, rc.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	return s, nil
}

func CreateClusterHeadlessService(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster) error {
	svc := c.GetHeadlessService()

	if err := controllerutil.SetOwnerReference(c, svc, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceService(ctx, rc, svc); err != nil {
		return fmt.Errorf("failed to replace headless service: %w", err)
	}

	return nil
}
