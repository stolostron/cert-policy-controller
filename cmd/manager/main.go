// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

package main

import (
	"flag"
	"os"
	"time"

	"github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/apis"
	"github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/controller"
	"k8s.io/klog"

	common "github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/common"
	policyStatusHandler "github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/controller/grcpolicy"
	"github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/webhook"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	//logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	var clusterName, namespace, eventOnParent, defaultDuration string
	var frequency uint
	var restartOrphanPods bool

	flag.StringVar(&clusterName, "cluster-name", "mcm-managed-cluster", "Name of the cluster")
	flag.BoolVar(&restartOrphanPods, "restart-orphan-pods", false, "Pods that are not part of a controller")
	flag.UintVar(&frequency, "update-frequency", 10, "The status update frequency (in seconds) of a mutation policy")
	flag.StringVar(&namespace, "watch-ns", "default", "Watched Kubernetes namespace")
	flag.StringVar(&eventOnParent, "parent-event", "ifpresent", "to also send status events on parent policy. options are: yes/no/ifpresent")
	flag.StringVar(&defaultDuration, "default-duration", "672h", "The default minimum duration allowed for certificatepolicies to be compliant, must be in golang time format")

	flag.Set("logtostderr", "true")

	flag.Parse()

	// Get a config to talk to the apiserver
	klog.Info("setting up client for manager")
	cfg, err := config.GetConfig()
	if err != nil {
		klog.Error(err, "unable to set up client config")
		os.Exit(1)
	}

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(cfg, manager.Options{})
	if err != nil {
		klog.Error(err, "unable to set up overall controller manager")
		os.Exit(1)
	}

	klog.Info("Registering Components.")

	// Setup Scheme for all resources
	klog.Info("setting up scheme")
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		klog.Error(err, "unable add APIs to scheme")
		os.Exit(1)
	}

	// Setup all Controllers
	klog.Info("Setting up controller")
	if err := controller.AddToManager(mgr); err != nil {
		klog.Error(err, " unable to register controllers to the manager")
		os.Exit(1)
	}

	klog.Info("setting up webhooks")
	if err := webhook.AddToManager(mgr); err != nil {
		klog.Error(err, "unable to register webhooks to the manager")
		os.Exit(1)
	}

	duration, err := time.ParseDuration(defaultDuration)
	if err != nil {
		klog.Errorf("Error parsing command line argument --default-duration, %s", err.Error())
		os.Exit(1)
	}

	// Initialize some variables
	generatedClient := kubernetes.NewForConfigOrDie(mgr.GetConfig())
	common.Initialize(generatedClient, cfg)
	policyStatusHandler.Initialize(generatedClient, mgr, clusterName, namespace, eventOnParent, duration)
	// PeriodicallyExecGRCPolicies is the go-routine that periodically checks the policies and does the needed work to make sure the desired state is achieved
	go policyStatusHandler.PeriodicallyExecGRCPolicies(frequency)

	// Start the Cmd
	klog.Info("Starting the Cmd.")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		klog.Error(err, "unable to run the manager")
		os.Exit(1)
	}
}
