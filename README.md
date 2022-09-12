[comment]: # ( Copyright Contributors to the Open Cluster Management project )

# Certificate Policy Controller

Open Cluster Management - Certificate Policy Controller

[![Build](https://img.shields.io/badge/build-Prow-informational)](https://prow.ci.openshift.org/?repo=stolostron%2Fcert-policy-controller) [![KinD tests](https://github.com/stolostron/cert-policy-controller/actions/workflows/kind.yml/badge.svg?branch=main&event=push)](https://github.com/stolostron/cert-policy-controller/actions/workflows/kind.yml) [![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

## Description

The Certificate Policy Controller is a controller that watches `CertificatePolicies` created to monitor a Kubernetes cluster to ensure all certificates in given namespaces will not expire within a given amount of time. The `CertificatePolicy` is the Custom Resource Definition (CRD), created for this controller to monitor. The controller can be run as a stand-alone program or as an integrated part of governing risk with the Open Cluster Management project.

In addition to checking the expiration of certificates, several optional checks are also available:

| Field | Description |
| ---- | ---- |
| minimumDuration | Required: Parameter specifies the smallest duration (in hours) before a certificate is considered non-compliant. When the certificate expiration is greater than the minimumDuration, then the certificate is considered compliant. Default value is 100h. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| minimumCADuration | Optional: Identify signing certificates that expire soon with a different value from other certificates.  If not specified CA certificate expiration is managed with the `minimumDuration` setting. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| maximumDuration | Optional: Identify certificates that have been created with a duration that exceeds your desired limit. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| maximumCADuration | Optional: Identify signing certificates that have been created with a duration that exceeds your desired limit.  If not specified, the CA certificate maximum duration is monitored using the `maximumDuration` setting. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| allowedSANPattern | Optional: A regular expression that must match every SAN entry you have defined in your certificates. See Golang Regular Expression syntax for more inforamtion: https://golang.org/pkg/regexp/syntax/ |
| disallowedSANPattern | Optional: A regular expression that must not match any SAN entries you have defined in your certificates.  See Golang Regular Expression syntax for more inforamtion: https://golang.org/pkg/regexp/syntax/ |

This is an example spec of a `CertificatePolicy` object:

```
apiVersion: policy.open-cluster-management.io/v1
kind: CertificatePolicy
metadata:
  name: certificate-policy-1
  namespace: kube-system
  label:
    category: "System-Integrity"
spec:
  # include are the namespaces you want to watch certificatepolicies in, while exclude are the namespaces you explicitly do not want to watch
  namespaceSelector:
    include: ["default", "kube-*"]
    exclude: ["kube-system"]
  # Can be enforce or inform, however enforce doesn't do anything with regards to this controller
  remediationAction: inform
  # minimum duration is the least amount of time the certificate is still valid before it is considered non-compliant
  minimumDuration: 100h
```

Go to the [Contributing guide](CONTRIBUTING.md) to learn how to get involved!

## Usage

### Steps for development

  - Build code
    ```bash
    make build
    ```
  - Run controller locally against the Kubernetes cluster currently configured with `kubectl`
    ```bash
    export WATCH_NAMESPACE=<namespace>
    make run
    ```
    (`WATCH_NAMESPACE` can be any namespace on the cluster that you want the controller to monitor for policies.)

### Steps for deployment

  - Build container image
    ```bash
    make build-images
    ```
    - The image registry, name, and tag used in the image build, are configurable with:
      ```bash
      export REGISTRY=''  # (defaults to 'quay.io/stolostron')
      export IMG=''       # (defaults to the repository name)
      export TAG=''       # (defaults to 'latest')
      ```
  - Deploy controller to a cluster

    The controller is deployed to a namespace defined in `CONTROLLER_NAMESPACE` and monitors the namepace defined in `WATCH_NAMESPACE` for `CertificatePolicy` resources.

    1. Create the deployment namespaces
       ```bash
       make create-ns
       ```
       The deployment namespaces are configurable with:
       ```bash
       export CONTROLLER_NAMESPACE=''  # (defaults to 'open-cluster-management-agent-addon')
       export WATCH_NAMESPACE=''       # (defaults to 'managed')
       ```
    2. Deploy the controller and related resources
       ```bash
       make deploy
       ```
    **NOTE:** Please be aware of the community's [deployment images](https://github.com/stolostron/community#deployment-images) special note.

### Steps for test

  - Code linting
    ```bash
    make lint
    ```
  - Unit tests
    - Install prerequisites
      ```bash
      make test-dependencies
      ```
    - Run unit tests
      ```bash
      make test
      ```
  - E2E tests (**NOTE:** Currently there are no E2E tests to run)
    1. Prerequisites:
       - [docker](https://docs.docker.com/get-docker/)
       - [kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
    2. Start KinD cluster (make sure Docker is running first)
       ```bash
       make kind-bootstrap-cluster-dev
       ```
    3. Start the controller locally (see [Steps for development](#steps-for-development))
    4. Run E2E tests:
       ```bash
       export WATCH_NAMESPACE=managed
       make e2e-test
       ```

## References

- The `cert-policy-controller` is part of the `open-cluster-management` community. For more information, visit: [open-cluster-management.io](https://open-cluster-management.io).
- Check the [Security guide](SECURITY.md) if you need to report a security issue.

<!---
Date: 09/12/2022
-->
