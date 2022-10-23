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
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterSpec defines the desired state of Cluster
type ClusterSpec struct {
	AdminCertificateSecretName string             `json:"adminCertificateSecretName"`
	SecurityConfig             SecurityConfigSpec `json:"securityConfig,omitempty"`
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

func (c Cluster) GetSecurityConfig() *SecurityConfigSpec {
	return &c.Spec.SecurityConfig
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

func (c *Cluster) GetAdminCertificateSecretName() string {
	return c.Spec.AdminCertificateSecretName
}
