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
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IndexStateManagementPolicySpec defines the desired state of IndexStateManagementPolicy
type IndexStateManagementPolicySpec struct {
	ClusterName string `json:"clusterName"`
	Body        string `json:"body"`
}

// IndexStateManagementPolicyStatus defines the observed state of IndexStateManagementPolicy
type IndexStateManagementPolicyStatus struct {
	Version     int64  `json:"version"`
	SeqNo       int64  `json:"seqNo"`
	PrimaryTerm int64  `json:"primaryTerm"`
	PolicySHA1  string `json:"policySHA1"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IndexStateManagementPolicy is the Schema for the indexstatemanagementpolicies API
type IndexStateManagementPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IndexStateManagementPolicySpec   `json:"spec,omitempty"`
	Status IndexStateManagementPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IndexStateManagementPolicyList contains a list of IndexStateManagementPolicy
type IndexStateManagementPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IndexStateManagementPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IndexStateManagementPolicy{}, &IndexStateManagementPolicyList{})
}

func (p *IndexStateManagementPolicy) GetClusterAddress() string {
	return fmt.Sprintf(
		"https://%s-cluster-%s-headless.%s.svc:9200/_plugins/_ism/policies/%s",
		subresourceNamePrefix, p.Spec.ClusterName, p.GetNamespace(), p.GetName(),
	)
}

func (p *IndexStateManagementPolicy) GetPolicyBytesBuffer() io.Reader {
	return bytes.NewBufferString(p.Spec.Body)
}

func (p *IndexStateManagementPolicy) GetPolicyBytesSHA1() (string, error) {
	h := sha1.New()
	if _, err := h.Write([]byte(p.Spec.Body)); err != nil {
		return "", fmt.Errorf("failed to get policy body hash: %w", err)
	}

	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}
