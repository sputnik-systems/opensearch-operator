package factory

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func replaceSecret(ctx context.Context, rc client.Client, obj *corev1.Secret) error {
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

func replaceConfigMap(ctx context.Context, rc client.Client, obj *corev1.ConfigMap) error {
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

func replaceService(ctx context.Context, rc client.Client, obj *corev1.Service) error {
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

func replaceStatefulSet(ctx context.Context, rc client.Client, obj *appsv1.StatefulSet) error {
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

func replaceDeployment(ctx context.Context, rc client.Client, obj *appsv1.Deployment) error {
	if err := rc.Create(ctx, obj); err != nil {
		spec := obj.Spec
		n := client.ObjectKeyFromObject(obj)
		if err := rc.Get(ctx, n, obj); err != nil {
			return fmt.Errorf("failed to get Deployment object: %w", err)

		}

		obj.Spec = spec
		if err := rc.Update(ctx, obj); err != nil {
			return fmt.Errorf("failed to update Deployment object: %w", err)
		}
	}

	return nil
}

func getCertificateDN(ctx context.Context, rc client.Client, name, namespace string) (string, error) {
	obj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	n := client.ObjectKeyFromObject(obj)
	if err := rc.Get(ctx, n, obj); err != nil {
		return "", fmt.Errorf("failed to get Secret object: %w", err)

	}

	if _, ok := obj.Data["tls.crt"]; !ok {
		return "", errors.New("tls.crt key didn't find in Secret object")
	}

	pb, _ := pem.Decode(obj.Data["tls.crt"])

	c, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	return c.Subject.String(), nil
}
