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

package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
	"github.com/preved911/opensearch-operator/controllers/factory"
	"github.com/preved911/opensearch-operator/controllers/factory/ism"
)

// IndexStateManagementPolicyReconciler reconciles a IndexStateManagementPolicy object
type IndexStateManagementPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=opensearch.my.domain,resources=indexstatemanagementpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=opensearch.my.domain,resources=indexstatemanagementpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=opensearch.my.domain,resources=indexstatemanagementpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IndexStateManagementPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *IndexStateManagementPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	l.Info("started IndexStateManagementPolicy reconciling")

	p := &opensearchv1alpha1.IndexStateManagementPolicy{}
	if err := r.Get(ctx, req.NamespacedName, p); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		l.Error(err, "failed to get IndexStateManagementPolicy object for reconclie")

		return ctrl.Result{}, err
	}

	n := types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.ClusterName}
	c := &opensearchv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
	if err := r.Get(ctx, n, c); err != nil {
		if errors.IsNotFound(err) {
			l.Error(err, "corresponding Cluster resource not found")

			return ctrl.Result{}, err
		}

		l.Error(err, "failed to get Cluster object for reconclie")

		return ctrl.Result{}, err
	}

	n.Name = p.GetClusterCertificatesSecretName()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
	if err := r.Get(ctx, n, s); err != nil {
		if errors.IsNotFound(err) {
			l.Error(err, "corresponding cluster certificates Secret resource not found")

			return ctrl.Result{}, err
		}

		l.Error(err, "failed to get cluster certificates Secret object for reconclie")

		return ctrl.Result{}, err
	}
	pem := c.GetConfig().GetTransportLayerSSL()
	caPEM, _, err := factory.GetCaCertAndKeyPEM(s, pem)
	if err != nil {
		return ctrl.Result{}, err
	}
	certPEM, keyPEM, err := factory.GetCertAndKeyPEM(s, pem, "ADMIN")
	if err != nil {
		return ctrl.Result{}, err
	}

	if !p.DeletionTimestamp.IsZero() {
		if err = ism.RemovePolicy(ctx, l, p, caPEM, certPEM, keyPEM); err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(p, "opensearch.my.domain/policy")
		if err := r.Update(ctx, p); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, err
	}

	sha1, err := p.GetPolicyBytesSHA1()
	if err != nil {
		return ctrl.Result{}, err
	}

	if sha1 == p.Status.PolicySHA1 {
		return ctrl.Result{}, nil
	}
	p.Status.PolicySHA1 = sha1

	if err := ism.AddPolicy(ctx, l, p, caPEM, certPEM, keyPEM); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.Status().Update(ctx, p); err != nil {
		return ctrl.Result{}, err
	}

	if err := controllerutil.SetOwnerReference(c, p, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update ownerReference: %w", err)
	}

	controllerutil.AddFinalizer(p, "opensearch.my.domain/policy")
	if err := r.Update(ctx, p); err != nil {
		return ctrl.Result{}, err
	}

	l.Info("finished IndexStateManagementPolicy reconciling")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IndexStateManagementPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&opensearchv1alpha1.IndexStateManagementPolicy{}).
		Complete(r)
}
