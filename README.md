# ICP Certificate Policy Controller
## Description
A controller that watches certificates created and/or used within ICP/MCM to ensure they don't expire within a given amount of time.

## Usage
The controller watches for `CertPolicy` objects in Kubernetes. This is an example spec of a `CertPolicy` object:

```yaml
apiVersion: mcm-grcpolicy.ibm.com
kind: CertPolicy
metadata:
  name: certificate-policy-1
  namespace: kube-system
  label:
    category: "System-Integrity"
spec:
  namespaceSelector:
    include: ["default", "kube-*"]
    exclude: ["kube-system"]
  remediationAction: inform
  minimumDuration: 100h
```
