package factory

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"path/filepath"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

func GenNodeGroupCerts(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster, ng *opensearchv1alpha1.NodeGroup) error {
	cs, err := GetClusterSecret(ctx, rc, c, "certificates")
	if err != nil {
		return fmt.Errorf("failed to get Cluster secret object: %w", err)
	}

	ngs, err := GetNodeGroupSecret(ctx, rc, ng)
	if err != nil {
		return fmt.Errorf("failed to get NodeGroup secret object: %w", err)
	}

	var sans []string
	n := ng.GetSubresourceNamespacedName()
	for i := 0; i < ng.GetReplicas(); i++ {
		sans = append(sans, fmt.Sprintf("DNS:%s-%d", n.Name, i))
	}
	sans = append(sans, "DNS:localhost")
	sans = append(sans, fmt.Sprintf("DNS:%s", n.Name))
	sans = append(sans, fmt.Sprintf("DNS:%s.%s", n.Name, n.Namespace))
	sans = append(sans, fmt.Sprintf("DNS:%s.%s.svc", n.Name, n.Namespace))
	sans = append(sans, fmt.Sprintf("DNS:%s-headless", n.Name))
	sans = append(sans, fmt.Sprintf("DNS:%s-headless.%s", n.Name, n.Namespace))
	sans = append(sans, fmt.Sprintf("DNS:%s-headless.%s.svc", n.Name, n.Namespace))

	sans = append(sans, fmt.Sprintf("DNS:%s", ng.GetDiscoverySeedHosts()))
	sans = append(sans, fmt.Sprintf("DNS:%s.%s", ng.GetDiscoverySeedHosts(), n.Namespace))
	sans = append(sans, fmt.Sprintf("DNS:%s.%s.svc", ng.GetDiscoverySeedHosts(), n.Namespace))

	pem := c.GetConfig().GetTransportLayerSSL()
	if ngs.Data["esnode.pem"], ngs.Data["esnode-key.pem"], err = GetCertAndKeyPEM(cs, pem, ng.GetDiscoverySeedHosts(), sans...); err != nil {
		return fmt.Errorf("failed to generate admin cert or key: %w", err)
	}

	if err := ReplaceSecret(ctx, rc, ngs); err != nil {
		return fmt.Errorf("failed to update certificates: %w", err)
	}

	return nil
}

func GetNodeGroupSecret(ctx context.Context, rc client.Client, ng *opensearchv1alpha1.NodeGroup) (*corev1.Secret, error) {
	n := ng.GetSubresourceNamespacedName()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}

	s.Labels = ng.GetSubresourceLabels()

	if err := controllerutil.SetOwnerReference(ng, s, rc.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	return s, nil
}

func CreateNodeGroupService(ctx context.Context, rc client.Client, l logr.Logger, ng *opensearchv1alpha1.NodeGroup) error {
	svc := ng.GetService()

	if err := controllerutil.SetOwnerReference(ng, svc, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceService(ctx, rc, svc); err != nil {
		return fmt.Errorf("failed to replace service: %w", err)
	}

	return nil
}

func CreateNodeGroupHeadlessService(ctx context.Context, rc client.Client, l logr.Logger, ng *opensearchv1alpha1.NodeGroup) error {
	n := ng.GetSubresourceNamespacedName()
	n.Name = n.Name + "-headless"
	svc := ng.GetService()
	svc.Name = n.Name
	svc.Spec.ClusterIP = "None"

	if err := controllerutil.SetOwnerReference(ng, svc, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceService(ctx, rc, svc); err != nil {
		return fmt.Errorf("failed to replace headless service: %w", err)
	}

	return nil
}

func CreateNodeGroupStatefulSet(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster, ng *opensearchv1alpha1.NodeGroup) error {
	sts := ng.GetStatefulSet()
	if sc := c.GetSecurityConfig(); sc.Enabled {
		vn := "cluster-security-config"
		mp := "/usr/share/opensearch/config/opensearch-security"
		v := corev1.Volume{
			Name: vn,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: c.GetSubresourceNamespacedName().Name + "-securityconfigs",
				},
			},
		}
		vms := make([]corev1.VolumeMount, 0)

		addConfig := func(config string) {
			v.VolumeSource.Secret.Items = append(v.VolumeSource.Secret.Items, corev1.KeyToPath{Key: config, Path: config})
			vm := corev1.VolumeMount{
				MountPath: filepath.Join(mp, config),
				Name:      vn,
				SubPath:   config,
			}
			vms = append(vms, vm)
		}

		if sc.ActionGroups != nil {
			addConfig("action_groups.yml")
		}
		if sc.Config != nil {
			addConfig("config.yml")
		}
		if sc.InternalUsers != nil {
			addConfig("internal_users.yml")
		}
		if sc.Roles != nil {
			addConfig("roles.yml")
		}
		if sc.RolesMapping != nil {
			addConfig("roles_mapping.yml")
		}
		if sc.Tenants != nil {
			addConfig("tenants.yml")
		}

		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, v)
		sts.Spec.Template.Spec.Containers[0].VolumeMounts = append(
			sts.Spec.Template.Spec.Containers[0].VolumeMounts,
			vms...,
		)
	}

	if err := controllerutil.SetOwnerReference(ng, sts, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceStatefulSet(ctx, rc, sts); err != nil {
		return fmt.Errorf("failed to replace StatefulSet: %w", err)
	}

	return nil
}

var (
	nodeGroupConfigTemplate = `---
cluster.initial_cluster_manager_nodes:
{{- range .InitialClusterManagerNodes}}
- {{ . }}
{{- end }}

# Bind to all interfaces because we don't know what IP address Docker will assign to us.
network.host: 0.0.0.0

# Setting network.host to a non-loopback address enables the annoying bootstrap checks. "Single-node" mode disables them again.
# discovery.type: single-node
# Start OpenSearch Security Demo Configuration
# WARNING: revise all the lines below before you go into production

plugins.security.ssl.transport.pemcert_filepath: esnode.pem
plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: {{ .HTTPEnabled }}
plugins.security.ssl.http.pemcert_filepath: esnode.pem
plugins.security.ssl.http.pemkey_filepath: esnode-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem

plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true

plugins.security.nodes_dn:
- CN={{ .DiscoverySeedHosts }},{{ .DistinguishedName }}

plugins.security.authcz.admin_dn:
- CN=ADMIN,{{ .DistinguishedName }}

plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [
  ".opendistro-alerting-config",
  ".opendistro-alerting-alert*",
  ".opendistro-anomaly-results*",
  ".opendistro-anomaly-detector*",
  ".opendistro-anomaly-checkpoints",
  ".opendistro-anomaly-detection-state",
  ".opendistro-reports-*",
  ".opendistro-notifications-*",
  ".opendistro-notebooks",
  ".opendistro-asynchronous-search-response*",
]
`
)

type NodeGroupConfig struct {
	DiscoverySeedHosts         string
	InitialClusterManagerNodes []string
	DistinguishedName          string
	HTTPEnabled                bool
}

func GenNodeGroupConfig(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster, ng *opensearchv1alpha1.NodeGroup) error {
	n := ng.GetSubresourceNamespacedName()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}

	cm.Labels = ng.GetSubresourceLabels()

	if err := controllerutil.SetOwnerReference(ng, cm, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	tmpl, err := template.New("").Parse(nodeGroupConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	dn := c.GetConfig().
		GetTransportLayerSSL().
		GetDistinguishedName().
		String()
	cvs := NodeGroupConfig{
		DiscoverySeedHosts:         ng.GetDiscoverySeedHosts(),
		InitialClusterManagerNodes: c.Status.InitialClusterManagerNodes,
		DistinguishedName:          dn,
		HTTPEnabled:                true,
	}

	configBody := new(bytes.Buffer)
	if err := tmpl.Execute(configBody, cvs); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	if _, ok := cm.Data["opensearch.yml"]; !ok {
		cm.Data = make(map[string]string)
	}

	cm.Data["opensearch.yml"] = string(configBody.Bytes())
	if err := ReplaceConfigMap(ctx, rc, cm); err != nil {
		return fmt.Errorf("failed to replace configmap object: %w", err)
	}

	return nil
}
