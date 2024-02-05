// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

//nolint:gci
import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"github.com/spf13/pflag"
	"github.com/stolostron/go-log-utils/zaputil"
	apiRuntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"open-cluster-management.io/addon-framework/pkg/lease"
	extpolicyv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	policyv1 "open-cluster-management.io/cert-policy-controller/api/v1"
	controllers "open-cluster-management.io/cert-policy-controller/controllers"
	"open-cluster-management.io/cert-policy-controller/version"
)

var (
	metricsHost       = "0.0.0.0"
	metricsPort int32 = 8383
	scheme            = apiRuntime.NewScheme()
	setupLog          = ctrl.Log.WithName("setup")
)

// errNoNamespace indicates that a namespace could not be found for the current
// environment. This was taken from operator-sdk v0.19.4.
var errNoNamespace = fmt.Errorf("namespace not found for current environment")

func printVersion() {
	setupLog.Info("Using", "OperatorVersion", version.Version, "GoVersion", runtime.Version(),
		"GOOS", runtime.GOOS, "GOARCH", runtime.GOARCH)
}

//nolint:wsl
func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(extpolicyv1.AddToScheme(scheme))

	utilruntime.Must(policyv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// getWatchNamespace returns the Namespace the operator should be watching for changes.
// This was taken from operator-sdk v0.19.4.
func getWatchNamespace() (string, error) {
	// WatchNamespaceEnvVar is the constant for env variable WATCH_NAMESPACE
	// which specifies the Namespace to watch.
	// An empty value means the operator is running with cluster scope.
	watchNamespaceEnvVar := "WATCH_NAMESPACE"

	ns, found := os.LookupEnv(watchNamespaceEnvVar)
	if !found {
		return "", fmt.Errorf("%s must be set", watchNamespaceEnvVar)
	}

	return ns, nil
}

// getOperatorNamespace returns the namespace the operator should be running in.
// This was partially taken from operator-sdk v0.19.4.
func getOperatorNamespace() (string, error) {
	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		if os.IsNotExist(err) {
			return "", errNoNamespace
		}

		return "", fmt.Errorf("failed to retrieve operator namespace: %w", err)
	}

	ns := strings.TrimSpace(string(nsBytes))
	setupLog.Info("Found operator namespace", "Namespace", ns)

	return ns, nil
}

func startLeaseController(generatedClient kubernetes.Interface, hubConfigPath, clusterName string) {
	operatorNs, err := getOperatorNamespace()
	if err != nil {
		if errors.Is(err, errNoNamespace) {
			setupLog.Info("Skipping lease; not running in a cluster.")
		} else {
			setupLog.Error(err, "Failed to get operator namespace")
			os.Exit(1)
		}
	} else {
		setupLog.V(2).Info("Got operator namespace", "Namespace", operatorNs)
		setupLog.Info("Starting lease controller to report status")

		leaseUpdater := lease.NewLeaseUpdater(
			generatedClient,
			"cert-policy-controller",
			operatorNs,
		)

		hubCfg, err := clientcmd.BuildConfigFromFlags("", hubConfigPath)
		if err != nil {
			setupLog.Error(err, "Could not load hub config, lease updater not set with config")
		} else {
			leaseUpdater = leaseUpdater.WithHubLeaseConfig(hubCfg, clusterName)
		}

		go leaseUpdater.Start(context.TODO())
	}
}

func main() {
	zflags := zaputil.FlagConfig{
		LevelName:   "log-level",
		EncoderName: "log-encoder",
	}
	zflags.Bind(flag.CommandLine)

	klog.InitFlags(flag.CommandLine)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	var eventOnParent, defaultDuration, clusterName, hubConfigPath, targetKubeConfig, probeAddr string
	var frequency uint
	var enableLease, enableLeaderElection bool

	//nolint:gomnd
	pflag.UintVar(&frequency, "update-frequency", 10,
		"The status update frequency (in seconds) of a mutation policy",
	)
	pflag.StringVar(&eventOnParent, "parent-event", "ifpresent",
		"to also send status events on parent policy. options are: yes/no/ifpresent",
	)
	pflag.StringVar(&defaultDuration, "default-duration", "672h",
		"The default minimum duration allowed for certificatepolicies to be compliant, must be in golang time format",
	)
	pflag.BoolVar(&enableLease, "enable-lease", false,
		"If enabled, the controller will start the lease controller to report its status",
	)
	pflag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.",
	)
	pflag.StringVar(&hubConfigPath, "hub-kubeconfig-path",
		"/var/run/klusterlet/kubeconfig", "Path to the hub kubeconfig",
	)
	pflag.StringVar(
		&targetKubeConfig,
		"target-kubeconfig-path",
		"",
		"A path to an alternative kubeconfig for policy evaluation and enforcement.",
	)
	pflag.StringVar(&clusterName, "cluster-name", "default-cluster", "Name of the cluster")
	flag.StringVar(&probeAddr, "health-probe-bind-address",
		":8081", "The address the probe endpoint binds to.",
	)

	pflag.Parse()

	ctrlZap, err := zflags.BuildForCtrl()
	if err != nil {
		panic(fmt.Sprintf("Failed to build zap logger for controller: %v", err))
	}

	ctrl.SetLogger(zapr.NewLogger(ctrlZap))

	// send klog messages through our zap logger so they look the same (console vs JSON)
	klogZap, err := zaputil.BuildForKlog(zflags.GetConfig(), flag.CommandLine)
	if err != nil {
		setupLog.Error(err, "Failed to build zap logger for klog, those logs will not go through zap")
	} else {
		klog.SetLogger(zapr.NewLogger(klogZap).WithName("klog"))
	}

	printVersion()

	namespace, err := getWatchNamespace()
	if err != nil {
		setupLog.Error(err, "Failed to get watch namespace")
		os.Exit(1)
	}

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		setupLog.Error(err, "Failed to get config for apiserver")
		os.Exit(1)
	}

	options := ctrl.Options{
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "cert-policy-controller.open-cluster-management.io",
		MetricsBindAddress:     fmt.Sprintf("%s:%d", metricsHost, metricsPort),
		Namespace:              namespace,
		Scheme:                 scheme,
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

	var targetK8sClient kubernetes.Interface
	var targetK8sConfig *rest.Config

	if targetKubeConfig == "" {
		targetK8sConfig = cfg
		targetK8sClient = kubernetes.NewForConfigOrDie(targetK8sConfig)
	} else {
		var err error

		targetK8sConfig, err = clientcmd.BuildConfigFromFlags("", targetKubeConfig)
		if err != nil {
			setupLog.Error(err, "Failed to load the target kubeconfig", "path", targetKubeConfig)
			os.Exit(1)
		}

		targetK8sClient = kubernetes.NewForConfigOrDie(targetK8sConfig)

		setupLog.Info(
			"Overrode the target Kubernetes cluster for policy evaluation and enforcement", "path", targetKubeConfig,
		)
	}

	instanceName, _ := os.Hostname() // on an error, instanceName will be empty, which is ok

	r := &controllers.CertificatePolicyReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("certificatepolicy-controller"),
		InstanceName:    instanceName,
		TargetK8sClient: targetK8sClient,
		TargetK8sConfig: targetK8sConfig,
	}
	if err = ctrl.NewControllerManagedBy(mgr).
		For(&policyv1.CertificatePolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r); err != nil {
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

	_ = r.Initialize(namespace, eventOnParent, time.Duration(0)) /* #nosec G104 */
	// PeriodicallyExecCertificatePolicies is the go-routine that periodically checks the policies and
	// does the needed work to make sure the desired state is achieved
	go r.PeriodicallyExecCertificatePolicies(context.TODO(), frequency, true)

	if enableLease {
		startLeaseController(generatedClient, hubConfigPath, clusterName)
	} else {
		setupLog.Info("Status reporting is not enabled")
	}

	setupLog.Info("Starting the manager")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
