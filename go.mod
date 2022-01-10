module github.com/stolostron/cert-policy-controller

go 1.16

require (
	github.com/onsi/gomega v1.10.2
	github.com/open-cluster-management/addon-framework v0.0.0-20210621074027-a81f712c10c2
	github.com/operator-framework/operator-sdk v0.19.4
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.6.2
)

replace (
	github.com/go-logr/zapr => github.com/go-logr/zapr v0.4.0
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // CVE-2021-43565
	k8s.io/client-go => k8s.io/client-go v0.20.5
)
