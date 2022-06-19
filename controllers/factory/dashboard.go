package factory

import (
	"bytes"
	"context"
	"fmt"
	"html/template"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

var (
	dashboardConfigTemplate = `---
server.host: 0.0.0.0
# opensearch.hosts: ["https://{{ .NodeGroupServiceName }}:9200"]
opensearch.ssl.verificationMode: full
# opensearch.username: "kibanaserver"
# opensearch.password: "kibanaserver"
opensearch.requestHeadersAllowlist: [ authorization,securitytenant ]
server.ssl.enabled: true
server.ssl.certificate: /usr/share/opensearch-dashboards/config/client.pem
server.ssl.key: /usr/share/opensearch-dashboards/config/client-key.pem
opensearch.ssl.certificateAuthorities: [ "/usr/share/opensearch-dashboards/config/root-ca.pem" ]
# opensearch_security.multitenancy.enabled: true
# opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.cookie.secure: true
`
)

type DashboardConfig struct {
	NodeGroupServiceName string
}

func GenDashboardConfig(ctx context.Context, rc client.Client, l logr.Logger, ng *opensearchv1alpha1.NodeGroup, d *opensearchv1alpha1.Dashboard) error {
	n := d.GetSubresourceNamespacedName()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}

	cm.Labels = d.GetSubresourceLabels()

	if err := controllerutil.SetOwnerReference(d, cm, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	tmpl, err := template.New("").Parse(dashboardConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	cvs := DashboardConfig{
		NodeGroupServiceName: ng.Status.ServiceName,
	}

	configBody := new(bytes.Buffer)
	if err := tmpl.Execute(configBody, cvs); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	if _, ok := cm.Data["opensearch_dashboards.yml"]; !ok {
		cm.Data = make(map[string]string)
	}

	cm.Data["opensearch_dashboards.yml"] = string(configBody.Bytes())
	if err := ReplaceConfigMap(ctx, rc, cm); err != nil {
		return fmt.Errorf("failed to replace configmap object: %w", err)
	}

	return nil
}

func CreateDashboardService(ctx context.Context, rc client.Client, l logr.Logger, d *opensearchv1alpha1.Dashboard) error {
	svc := d.GetService()

	if err := controllerutil.SetOwnerReference(d, svc, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceService(ctx, rc, svc); err != nil {
		return fmt.Errorf("failed to replace service: %w", err)
	}

	return nil
}

func CreateDashboardDeployment(ctx context.Context, rc client.Client, l logr.Logger, ng *opensearchv1alpha1.NodeGroup, d *opensearchv1alpha1.Dashboard) error {
	volume := corev1.Volume{
		Name: "cluster-certs",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: ng.GetClusterCertificatesSecretName(),
				Items: []corev1.KeyToPath{
					{
						Key:  "root-ca.pem",
						Path: "root-ca.pem",
					},
					{
						Key:  "client.pem",
						Path: "client.pem",
					},
					{
						Key:  "client-key.pem",
						Path: "client-key.pem",
					},
				},
			},
		},
	}

	deploy := d.GetDeployment()
	deploy.Spec.Template.Spec.Volumes = append(
		deploy.Spec.Template.Spec.Volumes,
		volume,
	)

	if err := controllerutil.SetOwnerReference(d, deploy, rc.Scheme()); err != nil {
		return fmt.Errorf("failed to update ownerReference: %w", err)
	}

	if err := ReplaceDeployment(ctx, rc, deploy); err != nil {
		return fmt.Errorf("failed to replace StatefulSet: %w", err)
	}

	return nil
}
