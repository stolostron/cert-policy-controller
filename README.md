[comment]: # ( Copyright Contributors to the Open Cluster Management project )

# Certificate Policy Controller [![KinD tests](https://github.com/open-cluster-management/cert-policy-controller/actions/workflows/kind.yml/badge.svg?branch=main&event=push)](https://github.com/open-cluster-management/cert-policy-controller/actions/workflows/kind.yml)
## Description
A controller that watches certificatepolicies created to monitor a kubernetes cluster to ensure certificates don't expire within a given amount of time. The controller shows whether or not a given `CertificatePolicy` is compliant.
In addition to checking the expiration of certificates, several optional checks are also available.

| Field | Description |
| ---- | ---- |
| minimumDuration | Required: Parameter specifies the smallest duration (in hours) before a certificate is considered non-compliant. When the certificate expiration is greater than the minimumDuration, then the certificate is considered compliant. Default value is 100h. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| minimumCADuration | Optional: Identify signing certificates that expire soon with a different value from other certificates.  If not specified CA certificate expiration is managed with the `minimumDuration` setting. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| maximumDuration | Optional: Identify certificates that have been created with a duration that exceeds your desired limit. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| maximumCADuration | Optional: Identify signing certificates that have been created with a duration that exceeds your desired limit.  If not specified, the CA certificate maximum duration is monitored using the `maximumDuration` setting. The parameter value uses the time duration format from Golang. See Golang Parse Duration for more information. |
| allowedSANPattern | Optional: A regular expression that must match every SAN entry you have defined in your certificates. See Golang Regular Expression syntax for more inforamtion: https://golang.org/pkg/regexp/syntax/ |
| disallowedSANPattern | Optional: A regular expression that must not match any SAN entries you have defined in your certificates.  See Golang Regular Expression syntax for more inforamtion: https://golang.org/pkg/regexp/syntax/ |


## Usage
The controller can be run as a stand-alone program or as an integrated part of governing risk with Red Hat Advanced Cluster Management for Kubernetes.

`CertificatePolicy` is the custom resource definition created by this controller. It watches specific namespaces and shows whether or not those namespaces and the policy as a whole is compliant.

The controller watches for `CertificatePolicy` objects in Kubernetes. This is an example spec of a `CertificatePolicy` object:

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
