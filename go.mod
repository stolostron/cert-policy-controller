module github.com/open-cluster-management/cert-policy-controller

go 1.14

require (
	github.com/onsi/gomega v1.10.2
	github.com/open-cluster-management/addon-framework v0.0.0-20210414095446-30a5d245b8c7
	github.com/operator-framework/operator-sdk v0.19.4
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.6.2
)

replace (
	github.com/go-logr/zapr => github.com/go-logr/zapr v0.4.0
	k8s.io/client-go => k8s.io/client-go v0.20.5
)
