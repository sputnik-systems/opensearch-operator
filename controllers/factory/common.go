package factory

import (
	"fmt"
	// "strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	// opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

var ResourcesPrefixString = "oso"

func GetLabels(o metav1.Object, name string) map[string]string {
	var labels map[string]string
	if labels = o.GetLabels(); labels == nil {
		labels = make(map[string]string)
	}

	labels["opensearch.my.domain/managed-by"] = "opensearch-operator"
	labels["opensearch.my.domain/cluster-name"] = name

	return labels
}

func GetNamespacedName(o metav1.Object) types.NamespacedName {
	name := fmt.Sprintf("%s-%s", ResourcesPrefixString, o.GetName())
	return types.NamespacedName{Namespace: o.GetNamespace(), Name: name}
}
