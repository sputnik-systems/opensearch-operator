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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/preved911/opensearch-operator/controllers/factory/certificate"
)

// CertificateReconciler reconciles a Secret object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=apps,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Dashboard object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	l.Info("started certificates reconciling")

	for _, obj := range certificate.Get(req.NamespacedName.Name) {
		n := types.NamespacedName{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}

		l.V(1).WithValues(
			"kind", obj.GetObjectKind().GroupVersionKind().Kind,
			"name", obj.GetName(),
		).Info("proccessing")

		if err := r.Get(ctx, n, obj); err != nil {
			if errors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}

			l.Error(err, "failed to get object for reconclie")

			return ctrl.Result{}, err
		}

		if sts, ok := obj.(*appsv1.StatefulSet); ok {
			// sts.Spec.Template.ObjectMeta.Annotations
			sts.Spec.Template.Annotations = map[string]string{
				"opensearch.sputnik.systems/restartedAt": time.Now().Format(time.RFC3339),
			}
			if err := r.Update(ctx, sts); err != nil {
				return ctrl.Result{}, err
			}
		} else if deploy, ok := obj.(*appsv1.Deployment); ok {
			deploy.Spec.Template.Annotations = map[string]string{
				"opensearch.sputnik.systems/restartedAt": time.Now().Format(time.RFC3339),
			}
			if err := r.Update(ctx, deploy); err != nil {
				return ctrl.Result{}, err
			}
		}

		l.V(1).WithValues(
			"kind", obj.GetObjectKind().GroupVersionKind().Kind,
			"name", obj.GetName,
		).Info("restarted")
	}

	l.Info("finished certificates reconciling")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}
