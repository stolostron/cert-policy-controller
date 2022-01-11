module github.com/stolostron/cert-policy-controller

go 1.16

require (
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/open-cluster-management/addon-framework v0.0.0-20210621074027-a81f712c10c2
	github.com/spf13/pflag v1.0.5
	github.com/stolostron/governance-policy-propagator v0.0.0-20220106234408-4675151f7b90
	github.com/stretchr/testify v1.7.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.9.2
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // CVE-2021-43565
	k8s.io/client-go => k8s.io/client-go v0.21.3
)
