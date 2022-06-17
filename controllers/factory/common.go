package factory

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ReplaceSecret(ctx context.Context, rc client.Client, obj *corev1.Secret) error {
	if err := rc.Create(ctx, obj); err != nil {
		data := obj.Data
		n := client.ObjectKeyFromObject(obj)
		if err := rc.Get(ctx, n, obj); err != nil {
			return fmt.Errorf("failed to get Secret object: %w", err)

		}

		obj.Data = data
		if err := rc.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update Secret object: %w", err)
		}
	}

	return nil
}

func ReplaceConfigMap(ctx context.Context, rc client.Client, obj *corev1.ConfigMap) error {
	if err := rc.Create(ctx, obj); err != nil {
		data := obj.Data
		n := client.ObjectKeyFromObject(obj)
		if err := rc.Get(ctx, n, obj); err != nil {
			return fmt.Errorf("failed to get ConfigMap object: %w", err)

		}

		obj.Data = data
		if err := rc.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update ConfigMap object: %w", err)
		}
	}

	return nil
}

func ReplaceService(ctx context.Context, rc client.Client, obj *corev1.Service) error {
	if err := rc.Create(ctx, obj); err != nil {
		spec := obj.Spec
		n := client.ObjectKeyFromObject(obj)
		if err := rc.Get(ctx, n, obj); err != nil {
			return fmt.Errorf("failed to get Service object: %w", err)

		}

		obj.Spec = spec
		if err := rc.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update Service object: %w", err)
		}
	}

	return nil
}

func ReplaceStatefulSet(ctx context.Context, rc client.Client, obj *appsv1.StatefulSet) error {
	if err := rc.Create(ctx, obj); err != nil {
		spec := obj.Spec
		n := client.ObjectKeyFromObject(obj)
		if err := rc.Get(ctx, n, obj); err != nil {
			return fmt.Errorf("failed to get StatefulSet object: %w", err)

		}

		obj.Spec = spec
		if err := rc.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update StatefulSet object: %w", err)
		}
	}

	return nil
}
