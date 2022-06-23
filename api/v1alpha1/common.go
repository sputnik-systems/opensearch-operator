package v1alpha1

const (
	caCertLifeTimeYears   = 10
	certLifeTimeYears     = 1
	subresourceNamePrefix = "opensearch"

	IndexStateManagementPolicyProtectionFinalizer = "opensearch.my.domain/ism-policy-protection"
)

var (
	livenessProbeDefaultCommand = []string{
		"/bin/sh",
		"-c",
		`#!/usr/bin/env bash

set -e

status=$(curl --cacert /usr/share/opensearch/config/root-ca.pem \
     --cert /usr/share/opensearch/config/admin.pem \
     --key /usr/share/opensearch/config/admin-key.pem \
     --fail-with-body --silent \
     https://localhost:9200/_cluster/health | \
     python -c 'import json, sys; resp = json.load(sys.stdin); print(resp["status"])')

if ["$status" == "red"]
then
        exit 1
fi
`,
	}

	readinessProbeDefaultCommand = []string{
		"/bin/sh",
		"-c",
		`#!/usr/bin/env bash

set -e

curl --cacert /usr/share/opensearch/config/root-ca.pem \
     --cert /usr/share/opensearch/config/admin.pem \
     --key /usr/share/opensearch/config/admin-key.pem \
     --fail-with-body --silent \
     https://localhost:9200
`,
	}

	runAsNonRoot       = true
	privileged         = true
	runAsUser    int64 = 1000
	fsGroup      int64 = 1000
)
