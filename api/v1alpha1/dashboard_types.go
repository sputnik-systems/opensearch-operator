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
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// DashboardSpec defines the desired state of Dashboard
type DashboardSpec struct {
	NodeGroupName               string               `json:"nodeGroupName"`
	ClientCertificateSecretName string               `json:"clientCertificateSecretName"`
	ExtraConfigBody             string               `json:"extraConfigBody,omitempty"`
	Replicas                    int                  `json:"replicas"`
	ServiceSpec                 NodeGroupServiceSpec `json:"serviceSpec,omitempty"`
	// +kubebuilder:default="opensearchproject/opensearch-dashboards:2.0.1"
	Image           string            `json:"image,omitempty"`
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	ExtraEnvVars    []corev1.EnvVar   `json:"extraEnvVars,omitempty"`
}

// DashboardStatus defines the observed state of Dashboard
type DashboardStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Dashboard is the Schema for the dashboards API
type Dashboard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DashboardSpec   `json:"spec,omitempty"`
	Status DashboardStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DashboardList contains a list of Dashboard
type DashboardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Dashboard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Dashboard{}, &DashboardList{})
}

func (d *Dashboard) GetSubresourceNamespacedName() types.NamespacedName {
	kind := strings.ToLower(d.GroupVersionKind().Kind)
	name := fmt.Sprintf("%s-%s-%s", subresourceNamePrefix, kind, d.GetName())
	namespace := d.GetNamespace()

	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

func (d *Dashboard) GetSubresourceLabels() map[string]string {
	labels := d.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}

	labels["opensearch.my.domain/managed-by"] = "opensearch-operator"
	labels["opensearch.my.domain/dashboard-name"] = d.GetName()

	return labels
}

func (d *Dashboard) GetCertificateSecretName() string {
	return d.Spec.ClientCertificateSecretName
}

func (d *Dashboard) GetService() *corev1.Service {
	n := d.GetSubresourceNamespacedName()
	labels := d.GetSubresourceLabels()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     5601,
				},
			},
			Selector: labels,
		},
	}

	if d.Spec.ServiceSpec.Type != nil {
		svc.Spec.Type = *d.Spec.ServiceSpec.Type
	}

	if d.Spec.ServiceSpec.ExternalTrafficPolicy != nil {
		svc.Spec.ExternalTrafficPolicy = *d.Spec.ServiceSpec.ExternalTrafficPolicy
	}

	return svc
}

func (d *Dashboard) GetReplicas() int {
	return d.Spec.Replicas
}

func (d *Dashboard) GetEnvVars() []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{
			Name:  "OPENSEARCH_HOSTS",
			Value: fmt.Sprintf("[\"https://%s-nodegroup-%s:9200\"]", subresourceNamePrefix, d.Spec.NodeGroupName),
		},
	}

	return append(envs, d.Spec.ExtraEnvVars...)
}

func (d *Dashboard) GetContainers() []corev1.Container {
	return []corev1.Container{
		{
			Name:            "opensearch-dashboard",
			Image:           d.Spec.Image,
			ImagePullPolicy: d.Spec.ImagePullPolicy,
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
					Name:          "http",
					Protocol:      corev1.ProtocolTCP,
					ContainerPort: 5601,
				},
			},
			Env: d.GetEnvVars(),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "config",
					MountPath: "/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml",
					SubPath:   "opensearch_dashboards.yml",
				},
				{
					Name:      "client-certs",
					MountPath: "/usr/share/opensearch-dashboards/config/root-ca.pem",
					SubPath:   "root-ca.pem",
				},
				{
					Name:      "client-certs",
					MountPath: "/usr/share/opensearch-dashboards/config/client.pem",
					SubPath:   "client.pem",
				},
				{
					Name:      "client-certs",
					MountPath: "/usr/share/opensearch-dashboards/config/client-key.pem",
					SubPath:   "client-key.pem",
				},
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Port: intstr.IntOrString{
							Type:   intstr.String,
							StrVal: "http",
						},
						Scheme: corev1.URISchemeHTTPS,
					},
				},
				PeriodSeconds:    60,
				FailureThreshold: 10,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Port: intstr.IntOrString{
							Type:   intstr.String,
							StrVal: "http",
						},
						Scheme: corev1.URISchemeHTTPS,
					},
				},
				PeriodSeconds:    10,
				FailureThreshold: 3,
			},
		},
	}
}

func (d *Dashboard) GetDeployment() *appsv1.Deployment {
	n := d.GetSubresourceNamespacedName()
	labels := d.GetSubresourceLabels()

	replicas := int32(d.GetReplicas())
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					// InitContainers:  d.GetInitContainers(),
					Containers: d.GetContainers(),
					Volumes: []corev1.Volume{
						{
							Name: "client-certs",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: d.Spec.ClientCertificateSecretName,
									Items: []corev1.KeyToPath{
										{
											Key:  "ca.crt",
											Path: "root-ca.pem",
										},
										{
											Key:  "tls.crt",
											Path: "client.pem",
										},
										{
											Key:  "tls.key",
											Path: "client-key.pem",
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
											Key:  "opensearch_dashboards.yml",
											Path: "opensearch_dashboards.yml",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return deploy
}

func (d *Dashboard) GetRuntimeObject() client.Object {
	n := d.GetSubresourceNamespacedName()

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
}
