// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/spf13/pflag"
	apiRuntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policyv1 "github.com/open-cluster-management/cert-policy-controller/apis/policy/v1"
	"github.com/open-cluster-management/cert-policy-controller/pkg/common"
	controller "github.com/open-cluster-management/cert-policy-controller/pkg/controller/certificatepolicy"
	"github.com/open-cluster-management/cert-policy-controller/version"
	//+kubebuilder:scaffold:imports
)

var (
	metricsHost       = "0.0.0.0"
	metricsPort int32 = 8383
	scheme            = apiRuntime.NewScheme()
	setupLog          = ctrl.Log.WithName("setup")
)

var log = logf.Log.WithName("cmd")

func printVersion() {
	log.Info(fmt.Sprintf("Operator Version: %s", version.Version))
	log.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
	log.Info(fmt.Sprintf("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH))
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(policyv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// getWatchNamespace returns the Namespace the operator should be watching for changes.
// This was taken from operator-sdk v0.19.4.
func getWatchNamespace() (string, error) {
	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which specifies the Namespace to watch.
	// An empty value means the operator is running with cluster scope.
	var watchNamespaceEnvVar = "WATCH_NAMESPACE"

	ns, found := os.LookupEnv(watchNamespaceEnvVar)
	if !found {
		return "", fmt.Errorf("%s must be set", watchNamespaceEnvVar)
	}
	return ns, nil
}

func main() {

	var eventOnParent, defaultDuration, clusterName, hubConfigSecretNs, hubConfigSecretName string
	var frequency uint
	var enableLeaderElection bool
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	pflag.UintVar(&frequency, "update-frequency", 10, "The status update frequency (in seconds) of a mutation policy")
	pflag.StringVar(&eventOnParent, "parent-event", "ifpresent", "to also send status events on parent policy. options are: yes/no/ifpresent")
	pflag.StringVar(&defaultDuration, "default-duration", "672h", "The default minimum duration allowed for certificatepolicies to be compliant, must be in golang time format")
	pflag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	pflag.StringVar(&hubConfigSecretNs, "hubconfig-secret-ns", "open-cluster-management-agent-addon", "Namespace for hub config kube-secret")
	pflag.StringVar(&hubConfigSecretName, "hubconfig-secret-name", "cert-policy-controller-hub-kubeconfig", "Name of the hub config kube-secret")
	pflag.StringVar(&clusterName, "cluster-name", "default-cluster", "Name of the cluster")

	pflag.Parse()

	var duration time.Duration
	logf.SetLogger(zap.New())
	printVersion()

	namespace, err := getWatchNamespace()
	if err != nil {
		log.Error(err, "Failed to get watch namespace")
		os.Exit(1)
	}

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	options := ctrl.Options{
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "cert-policy-controller",
		MetricsBindAddress: fmt.Sprintf("%s:%d", metricsHost, metricsPort),
		Namespace:          namespace,
		Scheme:             scheme,
	}

	if strings.Contains(namespace, ",") {
		options.Namespace = ""
		options.NewCache = cache.MultiNamespacedCacheBuilder(strings.Split(namespace, ","))
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	setupLog.Info("Registering components")

	if err = (&controller.CertificatePolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("certificatepolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificatePolicy")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	var generatedClient kubernetes.Interface = kubernetes.NewForConfigOrDie(mgr.GetConfig())
	common.Initialize(&generatedClient, cfg)
	controller.Initialize(&generatedClient, mgr, namespace, eventOnParent, duration) /* #nosec G104 */
	// PeriodicallyExecCertificatePolicies is the go-routine that periodically checks the policies and does the needed work to make sure the desired state is achieved
	go controller.PeriodicallyExecCertificatePolicies(frequency, true)

	setupLog.Info("Starting the manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
