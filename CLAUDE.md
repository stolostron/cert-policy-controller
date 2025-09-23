# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The Certificate Policy Controller is a Kubernetes controller for Open Cluster Management that monitors and ensures certificates in specified namespaces don't expire within a configurable time period. It's built using the Kubebuilder framework and implements the controller-runtime pattern.

## Development Commands

### Building and Running
- **Build the controller**: `make build`
- **Run locally against current kubectl context**: `make run` (requires `WATCH_NAMESPACE` env var)
- **Build container image**: `make build-images`

### Testing
- **Install test dependencies**: `make test-dependencies`
- **Run unit tests**: `make test`
- **Run tests with coverage**: `make test-coverage`
- **E2E tests**: `make e2e-test` (requires KinD cluster setup)

### Development Environment
- **Start KinD cluster for development**: `make kind-bootstrap-cluster-dev`
- **Deploy controller to KinD**: `make deploy`
- **Debug deployment issues**: `make e2e-debug`

### Linting and Code Generation
- **Vet code**: `make vet`
- **Generate manifests and CRDs**: `make manifests`
- **Generate deepcopy code**: `make generate`

## Architecture

### Core Components

**CertificatePolicy CRD** (`api/v1/certificatepolicy_types.go`):
- Defines the policy specification for certificate validation
- Supports namespace selectors, minimum/maximum duration checks, and SAN pattern validation
- Includes both certificate and CA-specific duration settings

**Controller** (`controllers/certificatepolicy_controller.go`):
- Implements the reconciliation logic using controller-runtime
- Runs periodic checks via `PeriodicallyExecCertificatePolicies`
- Supports both regular and hosted deployment modes

**Certificate Utilities** (`controllers/util/certificates_util.go`):
- Contains core certificate validation and parsing logic
- Handles expiration checking, SAN validation, and duration compliance

### Key Features

- **Multi-mode operation**: Supports both standalone and Open Cluster Management integration
- **Namespace filtering**: Include/exclude patterns for targeted certificate monitoring
- **Flexible duration policies**: Separate settings for regular certificates and Certificate Authority certificates
- **SAN validation**: Regular expression patterns for allowed/disallowed Subject Alternative Names
- **Metrics integration**: Prometheus metrics for policy compliance status

### Configuration

The controller uses environment variables and command-line flags:
- `WATCH_NAMESPACE`: Comma-separated list of namespaces to monitor
- `--update-frequency`: Policy evaluation frequency in seconds (default: 10)
- `--enable-lease`: Enable status reporting to hub cluster
- `--target-kubeconfig-path`: Alternative kubeconfig for hosted mode

### Deployment Structure

- `deploy/crds/`: Custom Resource Definitions
- `deploy/rbac/`: Role-based access control manifests
- `deploy/manager/`: Controller deployment configuration
- `deploy/operator.yaml`: Complete deployment manifest

The controller operates in two primary modes:
1. **Regular mode**: Monitors certificates in the same cluster where it runs
2. **Hosted mode**: Uses separate kubeconfig to monitor certificates in a different cluster