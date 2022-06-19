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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NodeGroupSpec defines the desired state of NodeGroup
type NodeGroupSpec struct {
	// ClusterName is specify which Cluster resource corresponds to this NodeGroup
	ClusterName string               `json:"clusterName"`
	Roles       NodeGroupSpecRoles   `json:"roles"`
	ServiceSpec NodeGroupServiceSpec `json:"serviceSpec,omitempty"`
	Replicas    int                  `json:"replicas"`
	// +kubebuilder:default="Parallel"
	PodManagementPolicy appsv1.PodManagementPolicyType `json:"podManagementPolicy,omitempty"`
	// +kubebuilder:default="opensearchproject/opensearch:2.0.1"
	Image           string            `json:"image,omitempty"`
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// SecurityContext           *corev1.SecurityContext       `json:"securityContext,omitempty"`
	LivenessProbe             *corev1.Probe                    `json:"livenessProbe,omitempty"`
	ReadinessProbe            *corev1.Probe                    `json:"readinessProbe,omitempty"`
	StartupProbe              *corev1.Probe                    `json:"startupProbe,omitempty"`
	SecurityContext           *corev1.PodSecurityContext       `json:"securityContext,omitempty"`
	ExtraEnvVars              []corev1.EnvVar                  `json:"extraEnvVars,omitempty"`
	InitContainers            []corev1.Container               `json:"initContainers,omitempty"`
	PersistentVolumeClaimSpec corev1.PersistentVolumeClaimSpec `json:"persistentVolumeClaimSpec"`
}

// NodeGroupStatus defines the observed state of NodeGroup
type NodeGroupStatus struct {
	ServiceName string `json:"serviceName,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// NodeGroup is the Schema for the nodegroups API
type NodeGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeGroupSpec   `json:"spec,omitempty"`
	Status NodeGroupStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NodeGroupList contains a list of NodeGroup
type NodeGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NodeGroup{}, &NodeGroupList{})
}

type NodeGroupSpecRoles []NodeGroupSpecRole

// +kubebuilder:validation:Enum=cluster_manager;ingest;data;remote_cluster_client
type NodeGroupSpecRole string

func (ng *NodeGroup) GetSubresourceNamespacedName() types.NamespacedName {
	kind := strings.ToLower(ng.GroupVersionKind().Kind)
	name := fmt.Sprintf("%s-%s-%s", subresourceNamePrefix, kind, ng.GetName())
	namespace := ng.GetNamespace()

	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

func (ng *NodeGroup) GetSubresourceLabels() map[string]string {
	labels := ng.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}

	labels["opensearch.my.domain/managed-by"] = "opensearch-operator"
	labels["opensearch.my.domain/cluster-name"] = ng.GetClusterName()
	labels["opensearch.my.domain/nodegroup-name"] = ng.GetName()

	for _, role := range ng.Spec.Roles {
		if role == NodeGroupSpecRole("master") {
			labels["opensearch.my.domain/nogegroup-master-role"] = "exists"
		}
	}

	return labels
}

func (ng *NodeGroup) GetClusterName() string {
	return ng.Spec.ClusterName
}

func (ng *NodeGroup) GetDiscoverySeedHosts() string {
	return fmt.Sprintf("%s-cluster-%s-headless", subresourceNamePrefix, ng.Spec.ClusterName)
}

func (ng *NodeGroup) GetClusterCertificatesSecretName() string {
	return fmt.Sprintf("%s-cluster-%s-certificates", subresourceNamePrefix, ng.GetClusterName())
}

func (ng *NodeGroup) SetServiceNameStatus() {
	n := ng.GetSubresourceNamespacedName()
	ng.Status.ServiceName = n.Name
}

type NodeGroupServiceSpec struct {
	Type                  *corev1.ServiceType                      `json:"type,omitempty"`
	ExternalTrafficPolicy *corev1.ServiceExternalTrafficPolicyType `json:"externalTrafficPolicy,omitempty"`
}

func (ng *NodeGroup) GetService() *corev1.Service {
	n := ng.GetSubresourceNamespacedName()
	l := ng.GetSubresourceLabels()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
			Labels:    l,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
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

	if ng.Spec.ServiceSpec.Type != nil {
		svc.Spec.Type = *ng.Spec.ServiceSpec.Type
	}

	if ng.Spec.ServiceSpec.ExternalTrafficPolicy != nil {
		svc.Spec.ExternalTrafficPolicy = *ng.Spec.ServiceSpec.ExternalTrafficPolicy
	}

	return svc
}

func (ng *NodeGroup) GetReplicas() int {
	return ng.Spec.Replicas
}

func (ng *NodeGroup) GetNodeNames() []string {
	names := make([]string, 0)

	prefix := ng.GetSubresourceNamespacedName().Name
	for i := 0; i < ng.GetReplicas(); i++ {
		names = append(names, fmt.Sprintf("%s-%d", prefix, i))
	}

	return names
}

func (ng *NodeGroup) GetRoles() NodeGroupSpecRoles {
	return ng.Spec.Roles
}

func (r NodeGroupSpecRoles) IsClusterManager() bool {
	for _, role := range r {
		if role == "cluster_manager" {
			return true
		}
	}

	return false
}

func (r NodeGroupSpecRoles) String() string {
	roles := make([]string, 0)

	for _, role := range r {
		roles = append(roles, string(role))
	}

	return strings.Join(roles, ",")
}

func (ng *NodeGroup) GetPodSecurityContext() *corev1.PodSecurityContext {
	if ng.Spec.SecurityContext != nil {
		return ng.Spec.SecurityContext
	}

	return &corev1.PodSecurityContext{
		//
		// doesn't supported yet
		//
		// Sysctls: []corev1.Sysctl{
		// 	{
		// 		Name:  "vm.max_map_count",
		// 		Value: "262144",
		// 	},
		// },
		//
		// it was be good to temporary disable this
		// and revert after native support vm.max_map_count sysctl
		// with kubelet will be implemented
		//
		// RunAsNonRoot: &runAsNonRoot,
		// RunAsUser:    &runAsUser,
		FSGroup: &fsGroup,
	}
}

func (ng *NodeGroup) GetInitContainers() []corev1.Container {
	return append(
		ng.Spec.InitContainers,
		corev1.Container{
			Name:  "sysctl-hack",
			Image: "busybox",
			SecurityContext: &corev1.SecurityContext{
				Privileged: &privileged,
			},
			Args: []string{
				"sysctl",
				"-w",
				"vm.max_map_count=262144",
			},
		},
	)
}

func (ng *NodeGroup) GetContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            "opensearch",
			Image:           ng.Spec.Image,
			ImagePullPolicy: ng.Spec.ImagePullPolicy,
			SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{
						"ALL",
					},
				},
				RunAsNonRoot: &runAsNonRoot,
				RunAsUser:    &runAsUser,
			},
			Ports: []corev1.ContainerPort{
				{
					Name:          "transport",
					Protocol:      corev1.ProtocolTCP,
					ContainerPort: 9300,
				},
				{
					Name:          "http",
					Protocol:      corev1.ProtocolTCP,
					ContainerPort: 9200,
				},
			},
			Env:            ng.GetEnvVars(),
			VolumeMounts:   ng.GetVolumeMounts(),
			LivenessProbe:  ng.GetLivenessProbe(),
			ReadinessProbe: ng.GetReadinessProbe(),
			StartupProbe:   ng.GetStartupProbe(),
		},
	}
}

func (ng *NodeGroup) GetVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      "data",
			MountPath: "/usr/share/opensearch/data",
		},
		{
			Name:      "config",
			MountPath: "/usr/share/opensearch/config/opensearch.yml",
			SubPath:   "opensearch.yml",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/root-ca.pem",
			SubPath:   "root-ca.pem",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/root-ca-key.pem",
			SubPath:   "root-ca-key.pem",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/client.pem",
			SubPath:   "client.pem",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/client-key.pem",
			SubPath:   "client-key.pem",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/admin.pem",
			SubPath:   "admin.pem",
		},
		{
			Name:      "cluster-certs",
			MountPath: "/usr/share/opensearch/config/admin-key.pem",
			SubPath:   "admin-key.pem",
		},
		{
			Name:      "nodegroup-certs",
			MountPath: "/usr/share/opensearch/config/esnode.pem",
			SubPath:   "esnode.pem",
		},
		{
			Name:      "nodegroup-certs",
			MountPath: "/usr/share/opensearch/config/esnode-key.pem",
			SubPath:   "esnode-key.pem",
		},
	}
}

func (ng *NodeGroup) GetEnvVars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{
			Name:  "cluster.name",
			Value: ng.GetClusterName(),
		},
		{
			Name:  "discovery.seed_hosts",
			Value: ng.GetDiscoverySeedHosts(),
		},
		{
			Name: "node.name",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name:  "node.roles",
			Value: ng.GetRoles().String(),
		},
	}

	return append(envs, ng.Spec.ExtraEnvVars...)
}

func (ng *NodeGroup) GetVolumes() []corev1.Volume {
	n := ng.GetSubresourceNamespacedName()

	return []corev1.Volume{
		{
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
							Key:  "root-ca-key.pem",
							Path: "root-ca-key.pem",
						},
						{
							Key:  "client.pem",
							Path: "client.pem",
						},
						{
							Key:  "client-key.pem",
							Path: "client-key.pem",
						},
						{
							Key:  "admin.pem",
							Path: "admin.pem",
						},
						{
							Key:  "admin-key.pem",
							Path: "admin-key.pem",
						},
					},
				},
			},
		},
		{
			Name: "nodegroup-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: n.Name,
					Items: []corev1.KeyToPath{
						{
							Key:  "esnode.pem",
							Path: "esnode.pem",
						},
						{
							Key:  "esnode-key.pem",
							Path: "esnode-key.pem",
						},
					},
				},
			},
		},
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: n.Name,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "opensearch.yml",
							Path: "opensearch.yml",
						},
					},
				},
			},
		},
	}
}

func (ng *NodeGroup) GetLivenessProbe() *corev1.Probe {
	if ng.Spec.LivenessProbe != nil {
		return ng.Spec.LivenessProbe
	}

	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: livenessProbeDefaultCommand,
			},
		},
		PeriodSeconds:    30,
		FailureThreshold: 10,
	}
}

func (ng *NodeGroup) GetReadinessProbe() *corev1.Probe {
	if ng.Spec.ReadinessProbe != nil {
		return ng.Spec.ReadinessProbe
	}

	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: readinessProbeDefaultCommand,
			},
		},
		PeriodSeconds:    10,
		FailureThreshold: 3,
	}
}

func (ng *NodeGroup) GetStartupProbe() *corev1.Probe {
	if ng.Spec.StartupProbe != nil {
		return ng.Spec.StartupProbe
	}

	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: readinessProbeDefaultCommand,
			},
		},
		PeriodSeconds:    10,
		FailureThreshold: 60,
	}
}

func (ng *NodeGroup) GetStatefulSet() *appsv1.StatefulSet {
	n := ng.GetSubresourceNamespacedName()
	labels := ng.GetSubresourceLabels()
	roles := ng.GetRoles()
	if roles.IsClusterManager() {
		labels["opensearch.my.domain/nogegroup-cluster-manager-role"] = "exists"
	}

	replicas := int32(ng.GetReplicas())
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:            &replicas,
			ServiceName:         n.Name + "-headless",
			PodManagementPolicy: ng.Spec.PodManagementPolicy,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					SecurityContext: ng.GetPodSecurityContext(),
					InitContainers:  ng.GetInitContainers(),
					Containers:      ng.GetContainers(),
					Volumes:         ng.GetVolumes(),
				},
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "data",
					},
					Spec: ng.Spec.PersistentVolumeClaimSpec,
				},
			},
		},
	}

	return sts
}
