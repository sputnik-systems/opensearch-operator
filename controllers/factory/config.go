package factory

// import (
// 	"bytes"
// 	"context"
// 	"fmt"
// 	"html/template"
//
// 	"github.com/go-logr/logr"
// 	corev1 "k8s.io/api/core/v1"
// 	"k8s.io/apimachinery/pkg/api/errors"
// 	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
// 	"sigs.k8s.io/controller-runtime/pkg/client"
// 	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
//
// 	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
// )

var (
	nodeGroupConfigTemplate = `---
cluster.name: opensearch-cluster

node.roles:
{{- range .Node.Roles }}
- {{ . }}
{{- end }}

# Bind to all interfaces because we don't know what IP address Docker will assign to us.
network.host: 0.0.0.0

# Setting network.host to a non-loopback address enables the annoying bootstrap checks. "Single-node" mode disables them again.
# discovery.type: single-node
# Start OpenSearch Security Demo Configuration
# WARNING: revise all the lines below before you go into production

plugins:
  security:
    ssl:
      transport:
        pemcert_filepath: esnode.pem
        pemkey_filepath: esnode-key.pem
        pemtrustedcas_filepath: root-ca.pem
        enforce_hostname_verification: false
      http:
        enabled: true
        pemcert_filepath: esnode.pem
        pemkey_filepath: esnode-key.pem
        pemtrustedcas_filepath: root-ca.pem
    allow_unsafe_democertificates: true
    allow_default_init_securityindex: true
    authcz:
      admin_dn:
        - CN=ADMIN,{{ .DN }}
    audit.type: internal_opensearch
    enable_snapshot_restore_privilege: true
    check_snapshot_restore_write_privileges: true
    restapi:
      roles_enabled: ["all_access", "security_rest_api_access"]
    system_indices:
      enabled: true
      indices:
        [
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

// func GenNodeGroupConfig(ctx context.Context, rc client.Client, l logr.Logger, c *opensearchv1alpha1.NodeGroup) error {
// 	var err error
//
// 	n := GetNamespacedName(c)
// 	cm := &corev1.ConfigMap{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      n.Name,
// 			Namespace: n.Namespace,
// 		},
// 	}
// 	if err = rc.Get(ctx, n, cm); err != nil {
// 		if !errors.IsNotFound(err) {
// 			return fmt.Errorf("failed to get config configmap: %w", err)
// 		}
//
// 		if err = rc.Create(ctx, cm); err != nil {
// 			return fmt.Errorf("failed to create empty configmap object: %w", err)
// 		}
// 	}
//
// 	cm.Labels = GetLabels(c, c.GetObject())
//
// 	if err := controllerutil.SetOwnerReference(c, cm, rc.Scheme()); err != nil {
// 		return fmt.Errorf("failed to update ownerReference: %w", err)
// 	}
//
// 	tmpl, err := template.New("").Parse(configTemplate)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse template: %w", err)
// 	}
//
// 	subj := opensearchv1alpha1.SubjectPEM("")
// 	if c.GetConfig().GetPlugins().GetSecurity().GetSSL() != nil {
// 		subj = *c.GetConfig().GetPlugins().GetSecurity().GetSSL().GetTransport().GetPEM().GetSubject()
// 	}
//
// 	commonDN := (&subj).ParseNamePKIX()
// 	adminDN := commonDN
// 	adminDN.CommonName = "CN=ADMIN"
//
// 	configValues := Config{
// 		HTTP: ConfigHTTP{
// 			Enabled: false,
// 		},
// 		DN: ConfigDN{
// 			Admin: []string{adminDN.String()},
// 			Nodes: []string{},
// 		},
// 	}
// 	for i := 0; i < replicas; i++ {
// 		nodeDN := commonDN
// 		nodeDN.CommonName = fmt.Sprintf("%s-%d", c.GetObject().GetName(), i)
// 		configValues.DN.Nodes = append(configValues.DN.Nodes, nodeDN.String())
// 	}
//
// 	configBody := new(bytes.Buffer)
// 	if err := tmpl.Execute(configBody, configValues); err != nil {
// 		return fmt.Errorf("failed to execute template: %w", err)
// 	}
//
// 	if _, ok := cm.Data["opensearch.yml"]; !ok {
// 		cm.Data = make(map[string]string)
// 	}
//
// 	cm.Data["opensearch.yaml"] = string(configBody.Bytes())
// 	if err := rc.Update(ctx, cm); err != nil {
// 		return fmt.Errorf("failed to update configmap: %w", err)
// 	}
//
// 	return nil
// }
