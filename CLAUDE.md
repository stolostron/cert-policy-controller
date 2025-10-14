# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

The Certificate Policy Controller is a Kubernetes controller that monitors certificates in specified namespaces to ensure they don't expire within a configured timeframe. It's part of the Open Cluster Management (OCM) governance suite and runs as a policy controller on managed clusters.

## Common Development Commands

### Building
```bash
# Build the controller binary (CGO enabled)
make build

# Build container image
make build-images

# Override image registry/name/tag
export REGISTRY='quay.io/stolostron'  # default
export IMG='cert-policy-controller'    # default
export TAG='latest'                    # default
```

### Running Locally
```bash
# Run controller against current kubectl context
export WATCH_NAMESPACE=<namespace>
make run
```

### Testing
```bash
# Install test dependencies (required before first test run)
make test-dependencies

# Run unit tests
make test

# Run unit tests with coverage
make test-coverage

# Run linting and code checks
make lint
make vet
```

### E2E Testing with KinD
```bash
# Create KinD cluster and install CRDs
make kind-bootstrap-cluster-dev

# Deploy controller to KinD (after building image)
make kind-deploy-controller-dev

# Run e2e tests (requires controller running locally or in cluster)
export WATCH_NAMESPACE=managed
make e2e-test

# Run e2e tests with coverage
make e2e-test-coverage

# Debug e2e issues
make e2e-debug

# Clean up KinD cluster
make kind-delete-cluster
```

### Generating Code and Manifests
```bash
# Generate CRD manifests and RBAC
make manifests

# Generate DeepCopy methods
make generate

# Generate operator.yaml from kustomize
make generate-operator-yaml
```

### Deployment
```bash
# Deploy to cluster (uses KIND_NAMESPACE and WATCH_NAMESPACE)
make deploy

# Configure deployment namespaces
export KIND_NAMESPACE='open-cluster-management-agent-addon'  # where controller runs
export WATCH_NAMESPACE='managed'                             # namespace to monitor
```

## Architecture

### Core Controller Pattern

This is a **polling-based controller** rather than a traditional event-driven Kubernetes controller. The main reconciliation happens in `PeriodicallyExecCertificatePolicies()` which runs on a fixed interval (default 10 seconds).

The standard `Reconcile()` function in `controllers/certificatepolicy_controller.go:83` only handles **delete events** to clean up metrics. All policy evaluation happens in the polling loop.

### Key Components

**main.go:80-242**
- Entry point that sets up the controller manager
- Configures logging using zapr and stolostron/go-log-utils
- Supports "hosted mode" where policies are evaluated on a different cluster than where they're stored (via `--target-kubeconfig-path` flag)
- Starts the periodic policy evaluation goroutine
- Optionally starts lease controller for status reporting to hub

**controllers/certificatepolicy_controller.go**
- `PeriodicallyExecCertificatePolicies()` (line 103): Main polling loop that processes all policies
- `ProcessPolicies()` (line 161): Evaluates each policy against selected namespaces
- `checkSecrets()` (line 247): Examines secrets in a namespace for certificate compliance
- `parseCertificate()` (line 313): Extracts and parses x509 certificates from secrets
- Compliance checks split across:
  - `isCertificateExpiring()` (line 384): Checks min duration before expiry
  - `isCertificateLongDuration()` (line 408): Checks max certificate lifetime
  - `isCertificateSANPatternMismatch()` (line 427): Validates SAN entries against regex patterns

**api/v1/certificatepolicy_types.go**
- CRD definitions for CertificatePolicy
- Supports multiple compliance checks:
  - `MinDuration`/`MinCADuration`: Minimum time before expiry
  - `MaxDuration`/`MaxCADuration`: Maximum certificate lifetime
  - `AllowedSANPattern`/`DisallowedSANPattern`: SAN validation via regex
- Status includes per-namespace compliance details and history (limited to 10 entries)

**pkg/common/namespace_selection.go**
- Implements namespace filtering logic
- Supports Include/Exclude patterns, MatchLabels, and MatchExpressions
- Pattern matching in `pkg/common/pattern_util.go`

**controllers/metric.go**
- Prometheus metrics for policy compliance state, evaluation time, and counters

### Certificate Discovery

Certificates are discovered from Kubernetes Secrets:
1. Secrets are filtered by `LabelSelector` from the policy spec
2. Default key is `tls.crt`, overrideable via `certificate_key_name` label on the secret
3. Certificate name for reporting uses labels in order: `certificate-name`, `certmanager.k8s.io/certificate-name`, or falls back to secret name
4. Only the first certificate in a chain is evaluated (leaf certificate)

### Hosted Mode

The controller supports a "hosted" deployment where:
- CertificatePolicy resources live in one cluster (management cluster)
- Certificate evaluation happens on a different cluster (managed cluster)
- Configured via `--target-kubeconfig-path` flag
- In this mode, `TargetK8sClient` points to the managed cluster while the controller-runtime client points to the management cluster

### Status Reporting

- Events are created on the parent Policy resource if OwnerReferences are set
- Status includes:
  - Overall `ComplianceState` (Compliant/NonCompliant)
  - Per-namespace `CompliancyDetails` with certificate lists
  - `History` array (max 10 entries) with timestamped messages
- Status messages formatted in `controllers/certificatepolicy_utils.go`

## Go Version

This project uses Go 1.24.0 (see go.mod:3)

## Important Implementation Details

### Polling Frequency
- Default update frequency is 10 seconds (configurable via `--update-frequency` flag)
- The controller waits for the frequency duration even if evaluation completes quickly
- See `loopWait()` function in `controllers/certificatepolicy_controller.go:152`

### Status Update Batching
- All policy status updates are batched per polling cycle
- Changes are detected by comparing current state with previous state
- Metrics are updated synchronously during policy processing

### Event Generation
- Events use the `EventOnParent` global variable (options: yes/no/ifpresent)
- Events are sent to OwnerReferences[0] if present
- Event names follow format: `{policy-name}.{timestamp-hex}`

### Test Structure
- Unit tests use Ginkgo/Gomega framework
- Controller tests in `controllers/certificatepolicy_controller_test.go`
- E2E tests in `test/e2e/` with labels for filtering (e.g., "hosted-mode")
- Test coverage minimum threshold: 65% (COVERAGE_MIN in Makefile)

## Contributing

All commits must be signed off with DCO:
```bash
git commit -s -m "your message"
```

This adds `Signed-off-by: Your Name <your@email.com>` to commits.

Before submitting PRs:
1. Run `make lint` and `make vet`
2. Run `make test` and ensure tests pass
3. Run e2e tests if making controller changes
