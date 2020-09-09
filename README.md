# CertificatePolicy Policy Controller
## Description
A controller that watches certificatepolicies created to monitor a kubernetes cluster to ensure certificates don't expire within a given amount of time. The controller shows whether or not a given `CertificatePolicy` is compliant.

## Usage
The controller can be run as a stand-alone program or as an integrated part of governing risk with Red Hat Advanced Cluster Management for Kubernetes.

`CertificatePolicy` is the custom resource definition created by this controller. It watches specific namespaces and shows whether or not those namespaces and the policy as a whole is compliant.

The controller watches for `CertificatePolicy` objects in Kubernetes. This is an example spec of a `CertificatePolicy` object:

```
apiVersion: policy.open-cluster-management.io/v1
kind: CertificatePolicy
metadata:
  name: certificate-policy-1
  namespace: default
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
