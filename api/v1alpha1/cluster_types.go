/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterSpec defines the desired state of Cluster
type ClusterSpec struct {
	Config         ConfigSpec         `json:"config,omitempty"`
	SecurityConfig SecurityConfigSpec `json:"securityConfig,omitempty"`
}

// ClusterStatus defines the observed state of Cluster
type ClusterStatus struct {
	InitialClusterManagerNodes []string `json:"initial_cluster_manager_nodes,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Cluster is the Schema for the clusters API
type Cluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec   `json:"spec,omitempty"`
	Status ClusterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterList contains a list of Cluster
type ClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Cluster{}, &ClusterList{})
}

func (c Cluster) GetSubresourceNamespacedName() types.NamespacedName {
	kind := strings.ToLower(c.GroupVersionKind().Kind)
	name := fmt.Sprintf("%s-%s-%s", subresourceNamePrefix, kind, c.GetName())
	namespace := c.GetNamespace()

	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

func (c Cluster) GetSubresourceLabels() map[string]string {
	labels := c.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}

	labels["opensearch.my.domain/managed-by"] = "opensearch-operator"
	labels["opensearch.my.domain/cluster-name"] = c.GetName()

	return labels
}

func (c *Cluster) SetInitialClusterManagerNodes(nodeNames ...string) {
	if len(c.Status.InitialClusterManagerNodes) == 0 {
		c.Status.InitialClusterManagerNodes = nodeNames
	}
}

func (c Cluster) GetConfig() *ConfigSpec {
	return &c.Spec.Config
}

func (c Cluster) GetSecurityConfig() *SecurityConfigSpec {
	return &c.Spec.SecurityConfig
}

// Config is defining opensearch.yml config file
type ConfigSpec struct {
	Plugins PluginsSpec `json:"plugins,omitempty"`
}

type PluginsSpec struct {
	Security SecuritySpec `json:"security,omitempty"`
}

type SecuritySpec struct {
	SSL SecureSocketsLayerSpec `json:"ssl,omitempty"`
}

type SecureSocketsLayerSpec struct {
	Transport PrivacyEnhancedMailFormatSpec `json:"transport,omitempty"`
	HTTP      PrivacyEnhancedMailFormatSpec `json:"http,omitempty"`
}

func (s *ConfigSpec) GetTransportLayerSSL() *PrivacyEnhancedMailFormatSpec {
	return &s.Plugins.Security.SSL.Transport
}

type PrivacyEnhancedMailFormatSpec struct {
	DN   string   `json:"distinguishedName,omitempty"`
	SANs []string `json:"subjectAltNames,omitempty"`
}

// +kubebuilder:object:generate=false
type Certificate struct {
	cert x509.Certificate
}

func (c *Certificate) AddSubjectAltName(san string) {
	kv := strings.Split(san, ":")
	switch kv[0] {
	case "DNS":
		c.cert.DNSNames = append(c.cert.DNSNames, kv[1])
	case "IP":
		ip := net.ParseIP(kv[1])
		if ip != nil {
			c.cert.IPAddresses = append(c.cert.IPAddresses, ip)
		}
	}
}

func (c *Certificate) AddCommonName(cn string) {
	c.cert.Subject.CommonName = cn
}

func (c *Certificate) GetX509() *x509.Certificate {
	return &c.cert
}

func (pem *PrivacyEnhancedMailFormatSpec) GetCertificate(isCa bool) *Certificate {
	c := &Certificate{}
	now := time.Now()
	c.cert = x509.Certificate{
		SerialNumber:          big.NewInt(int64(now.Year())),
		Subject:               pem.GetDistinguishedName(),
		NotBefore:             now,
		NotAfter:              now.AddDate(caCertLifeTimeYears, 0, 0),
		IsCA:                  isCa,
		BasicConstraintsValid: true,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	if !isCa {
		if len(pem.SANs) > 0 {
			c.cert.DNSNames = make([]string, 0)
			c.cert.IPAddresses = make([]net.IP, 0)

			for _, value := range pem.SANs {
				c.AddSubjectAltName(value)
			}
		}

		c.cert.NotAfter = now.AddDate(certLifeTimeYears, 0, 0)
	}

	return c
}

func (pem *PrivacyEnhancedMailFormatSpec) GetDistinguishedName() pkix.Name {
	subject := pkix.Name{}
	for _, substr := range strings.Split(pem.DN, ",") {
		kv := strings.Split(substr, "=")
		switch kv[0] {
		case "/C":
			subject.Country = append(subject.Country, kv[1])
		case "/O":
			subject.Organization = append(subject.Organization, kv[1])
		case "/OU":
			subject.OrganizationalUnit = append(subject.OrganizationalUnit, kv[1])
		case "/L":
			subject.Locality = append(subject.Locality, kv[1])
		case "/ST":
			subject.Province = append(subject.Province, kv[1])
		}
	}

	return subject
}

// SecurityConfig is defining opensearch security config files
type SecurityConfigSpec struct {
	// +kubebuilder:default=true
	Enabled       bool    `json:"enabled,omitempty"`
	ActionGroups  *string `json:"action_groups,omitempty"`
	Config        *string `json:"config,omitempty"`
	InternalUsers *string `json:"internal_users,omitempty"`
	Roles         *string `json:"roles,omitempty"`
	RolesMapping  *string `json:"roles_mapping,omitempty"`
	Tenants       *string `json:"tenants,omitempty"`
}

func (c *Cluster) GetHeadlessService() *corev1.Service {
	n := c.GetSubresourceNamespacedName()
	l := c.GetSubresourceLabels()
	l["opensearch.my.domain/nogegroup-cluster-manager-role"] = "exists"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name + "-headless",
			Namespace: n.Namespace,
			Labels:    l,
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeClusterIP,
			ClusterIP:                "None",
			PublishNotReadyAddresses: true,
			Ports: []corev1.ServicePort{
				{
					Name:     "transport",
					Protocol: corev1.ProtocolTCP,
					Port:     9300,
				},
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     9200,
				},
			},
			Selector: l,
		},
	}

	return svc
}
