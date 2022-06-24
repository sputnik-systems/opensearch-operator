package ism

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-logr/logr"

	opensearchv1alpha1 "github.com/preved911/opensearch-operator/api/v1alpha1"
)

type PolicyMetadata struct {
	Version     int64 `json:"_version"`
	PrimaryTerm int64 `json:"_primary_term"`
	SeqNo       int64 `json:"_seq_no"`
	// Policy      json.RawMessage `json:"policy"`
}

func AddPolicy(ctx context.Context, l logr.Logger, p *opensearchv1alpha1.IndexStateManagementPolicy, caPEM, certPEM, keyPEM []byte) error {
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return fmt.Errorf("failed to added root CA into cert pool")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse client cert and key: %w", err)
	}

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      rootCAs,
			},
		},
	}

	req, err := http.NewRequest("PUT", p.GetClusterAddress(), p.GetPolicyBytesBuffer())
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	if p.Status.SeqNo > 0 || p.Status.PrimaryTerm > 0 {
		q := req.URL.Query()
		q.Add("if_seq_no", strconv.FormatInt(p.Status.SeqNo, 10))
		q.Add("if_primary_term", strconv.FormatInt(p.Status.PrimaryTerm, 10))
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make http request: %w", err)
	}

	if resp.StatusCode >= 400 {
		l.Error(fmt.Errorf("status code: %d", resp.StatusCode), "policy creation request failed")

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read unsuccessful response body: %w", err)
		}

		l.Error(fmt.Errorf("body: %s", string(b)), "policy creation request failed")

		return errors.New("failed to make policy creation http request")
	}

	var meta PolicyMetadata
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return fmt.Errorf("failed to serialize response body: %w", err)
	}

	p.Status.Version = meta.Version
	p.Status.PrimaryTerm = meta.PrimaryTerm
	p.Status.SeqNo = meta.SeqNo

	return nil
}

func RemovePolicy(ctx context.Context, l logr.Logger, p *opensearchv1alpha1.IndexStateManagementPolicy, caPEM, certPEM, keyPEM []byte) error {
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return fmt.Errorf("failed to added root CA into cert pool")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse client cert and key: %w", err)
	}

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      rootCAs,
			},
		},
	}

	req, err := http.NewRequest("DELETE", p.GetClusterAddress(), nil)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make http request: %w", err)
	}

	if resp.StatusCode == 404 {
		return nil
	}

	if resp.StatusCode >= 400 {
		l.Error(fmt.Errorf("status code: %d", resp.StatusCode), "policy creation request failed")

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read unsuccessful response body: %w", err)
		}

		l.Error(fmt.Errorf("body: %s", string(b)), "policy creation request failed")

		return errors.New("failed to make policy creation http request")
	}

	return nil
}
