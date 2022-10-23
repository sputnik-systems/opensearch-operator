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
	"github.com/preved911/opensearch-operator/controllers/factory/certificate"
)

func CreateNodeGroupService(ctx context.Context, rc client.Client, l logr.Logger, ng *opensearchv1alpha1.NodeGroup) error {
	svc := ng.GetService()

	if err := controllerutil.SetOwnerReference(ng, svc, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := replaceService(ctx, rc, svc); err != nil {
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

	if err := replaceService(ctx, rc, svc); err != nil {
		return fmt.Errorf("failed to replace headless service: %w", err)
	}

	return nil
}

func CreateNodeGroupStatefulSet(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.Cluster, ng *opensearchv1alpha1.NodeGroup) error {
	sts := ng.GetStatefulSet()
	sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "admin-certs",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: c.GetAdminCertificateSecretName(),
				Items: []corev1.KeyToPath{
					{
						Key:  "tls.crt",
						Path: "admin.pem",
					},
					{
						Key:  "tls.key",
						Path: "admin-key.pem",
					},
				},
			},
		},
	})

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

	if err := replaceStatefulSet(ctx, rc, sts); err != nil {
		return fmt.Errorf("failed to replace StatefulSet: %w", err)
	}

	obj := ng.GetRuntimeObject()
	certificate.Add(ng.GetCertificateSecretName(), obj)
	certificate.Add(c.GetAdminCertificateSecretName(), obj)

	return nil
}

var (
	nodeGroupConfigTemplate = `---
cluster.initial_cluster_manager_nodes:
{{- range .InitialClusterManagerNodes}}
- {{ . }}
{{- end }}

network.host: 0.0.0.0

plugins.security.ssl.transport.pemcert_filepath: esnode.pem
plugins.security.ssl.transport.pemkey_filepath: esnode-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: esnode.pem
plugins.security.ssl.http.pemkey_filepath: esnode-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem

plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true

plugins.security.nodes_dn:
- {{ .NodeGroupDN }}

plugins.security.authcz.admin_dn:
- {{ .AdminDN }}

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

{{ .ExtraConfigBody }}
`
	nodeGroupEntrypointTemplate = `#!/usr/bin/env bash

set -euo pipefail
{{ range . }}
./bin/opensearch-plugin install --batch {{ . }}
{{ end }}
bash opensearch-docker-entrypoint.sh
`
)

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
		return fmt.Errorf("failed to parse opensearch.yml template: %w", err)
	}

	ngcs, err := getCertificateDN(ctx, rc, ng.GetCertificateSecretName(), n.Namespace)
	if err != nil {
		return fmt.Errorf("failed to parse nodgroup certificate subject: %w", err)
	}
	cacs, err := getCertificateDN(ctx, rc, c.GetAdminCertificateSecretName(), n.Namespace)
	if err != nil {
		return fmt.Errorf("failed to parse clsuter admin certificate subject: %w", err)
	}
	values := struct {
		DiscoverySeedHosts         string
		InitialClusterManagerNodes []string
		NodeGroupDN                string
		AdminDN                    string
		ExtraConfigBody            string
	}{
		DiscoverySeedHosts:         ng.GetDiscoverySeedHosts(),
		InitialClusterManagerNodes: c.Status.InitialClusterManagerNodes,
		NodeGroupDN:                ngcs,
		AdminDN:                    cacs,
		ExtraConfigBody:            ng.Spec.ExtraConfigBody,
	}
	body := new(bytes.Buffer)
	if err := tmpl.Execute(body, values); err != nil {
		return fmt.Errorf("failed to execute opensearch.yml template: %w", err)
	}

	if _, ok := cm.Data["opensearch.yml"]; !ok {
		cm.Data = make(map[string]string)
	}
	cm.Data["opensearch.yml"] = string(body.Bytes())

	body = new(bytes.Buffer)
	tmpl, err = template.New("").Parse(nodeGroupEntrypointTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse docker-entrypoint.sh template: %w", err)
	}

	if err := tmpl.Execute(body, ng.Spec.Plugins); err != nil {
		return fmt.Errorf("failed to execute docker-entrypoint.sh template: %w", err)
	}
	cm.Data["docker-entrypoint.sh"] = string(body.Bytes())

	if err := replaceConfigMap(ctx, rc, cm); err != nil {
		return fmt.Errorf("failed to replace configmap object: %w", err)
	}

	return nil
}
