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

	appsv1 "k8s.io/api/apps/v1"
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
	"github.com/preved911/opensearch-operator/controllers/factory/certificate"
)

// NodeGroupReconciler reconciles a NodeGroup object
type NodeGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=opensearch.my.domain,resources=nodegroups,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=opensearch.my.domain,resources=nodegroups/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=opensearch.my.domain,resources=nodegroups/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NodeGroup object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *NodeGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	l.Info("started NodeGroup reconciling")

	ng := &opensearchv1alpha1.NodeGroup{}
	err := r.Get(ctx, req.NamespacedName, ng)
	if err != nil {
		if errors.IsNotFound(err) {
			certificate.Remove(ng.GetRuntimeObject())

			return ctrl.Result{}, nil
		}

		l.Error(err, "failed to get NodeGroup object for reconclie")

		return ctrl.Result{}, err
	}

	n := types.NamespacedName{Namespace: ng.Namespace, Name: ng.Spec.ClusterName}
	c := &opensearchv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
	}
	err = r.Get(ctx, n, c)
	if err != nil {
		if errors.IsNotFound(err) {
			l.Error(err, "corresponding Cluster resource not found")

			return ctrl.Result{}, err
		}

		l.Error(err, "failed to get Cluster object for reconclie")

		return ctrl.Result{}, err
	}

	if ng.GetRoles().IsClusterManager() {
		c.SetInitialClusterManagerNodes(ng.GetNodeNames()...)
		if err := r.Status().Update(ctx, c); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err = controllerutil.SetOwnerReference(c, ng, r.Client.Scheme()); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update ownerReference: %w", err)
	}

	controllerutil.AddFinalizer(ng, "foregroundDeletion")

	if err := factory.GenNodeGroupConfig(ctx, r.Client, l, c, ng); err != nil {
		return ctrl.Result{}, err
	}

	if err := factory.CreateNodeGroupService(ctx, r.Client, l, ng); err != nil {
		return ctrl.Result{}, err
	}

	if err := factory.CreateNodeGroupHeadlessService(ctx, r.Client, l, ng); err != nil {
		return ctrl.Result{}, err
	}

	if err := factory.CreateNodeGroupStatefulSet(ctx, r.Client, l, c, ng); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.Update(ctx, ng); err != nil {
		return ctrl.Result{}, err
	}

	l.Info("finished NodeGroup reconciling")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&opensearchv1alpha1.NodeGroup{}).
		Owns(&opensearchv1alpha1.Dashboard{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.StatefulSet{}).
		Complete(r)
}
