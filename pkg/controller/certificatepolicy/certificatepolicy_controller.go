// Copyright (c) 2020 Red Hat, Inc.
package certificatepolicy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
	"github.com/open-cluster-management/cert-policy-controller/pkg/common"
	"github.com/open-cluster-management/cert-policy-controller/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const certNameLabel = "certificate-name"
const certManagerNameLabel = "certmanager.k8s.io/certificate-name"

const grcCategory = "system-and-information-integrity"

var clusterName = "managedCluster"

// availablePolicies is a cach all all available polices
var availablePolicies common.SyncedPolicyMap

// PlcChan a channel used to pass policies ready for update
var PlcChan chan *policyv1.CertificatePolicy

// KubeClient a k8s client used for k8s native resources
var KubeClient *kubernetes.Interface

var reconcilingAgent *ReconcileCertificatePolicy

// NamespaceWatched defines which namespace we can watch for the Certificate policies and ignore others
var NamespaceWatched string

// EventOnParent specifies if we also want to send events to the parent policy. Available options are yes/no/ifpresent
var EventOnParent string

// DefaultDuration is the default minimum duration (if one isn't specified in a policy) that a certificate can be valid for to be compliant
var DefaultDuration time.Duration

var log = logf.Log.WithName("controller_certificatepolicy")

// Initialize to initialize some controller varaibles
func Initialize(kClient *kubernetes.Interface, mgr manager.Manager, namespace, eventParent string, defaultDuration time.Duration) (err error) {
	KubeClient = kClient
	PlcChan = make(chan *policyv1.CertificatePolicy, 100) //buffering up to 100 policies for update

	NamespaceWatched = namespace

	EventOnParent = strings.ToLower(eventParent)

	DefaultDuration = defaultDuration
	return nil
}

// Add creates a new CertificatePolicy Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCertificatePolicy{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetEventRecorderFor("certificatepolicy-controller")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("certificatepolicy-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource CertificatePolicy
	pred := predicate.GenerationChangedPredicate{}
	err = c.Watch(&source.Kind{Type: &policyv1.CertificatePolicy{}}, &handler.EnqueueRequestForObject{}, pred)
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileCertificatePolicy implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCertificatePolicy{}

// ReconcileCertificatePolicy reconciles a CertificatePolicy object
type ReconcileCertificatePolicy struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	recorder record.EventRecorder
}

// Reconcile reads that state of the cluster for a CertificatePolicy object and makes changes based on the state read
// and what is in the CertificatePolicy.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCertificatePolicy) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling CertificatePolicy")

	if reconcilingAgent == nil {
		reconcilingAgent = r
	}
	// Fetch the CertificatePolicy instance
	instance := &policyv1.CertificatePolicy{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			handleRemovingPolicy(request.NamespacedName.Name)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		updateNeeded := false
		if ensureDefaultLabel(instance) {
			klog.Info("Label update needed")
			updateNeeded = true
		}
		if updateNeeded {
			if err := r.client.Update(context.Background(), instance); err != nil {
				klog.Info("Requeing due to error updating the label")
				return reconcile.Result{Requeue: true}, nil
			}
		}
		instance.Status.CompliancyDetails = nil //reset CompliancyDetails
		err := handleAddingPolicy(instance)
		if err != nil {
			klog.V(3).Infof("Failed to handleAddingPolicy")
		}
	}

	klog.Infof("reason: successful processing, subject: policy/%v, namespace: %v, according to policy: %v, additional-info: none\n", instance.Name, instance.Namespace, instance.Name)
	return reconcile.Result{}, nil
}

func ensureDefaultLabel(instance *policyv1.CertificatePolicy) bool {
	klog.V(3).Info("ensureDefaultLabel")
	//we need to ensure this label exists -> category: "System and Information Integrity"
	if instance.ObjectMeta.Labels == nil {
		newlbl := make(map[string]string)
		newlbl["category"] = grcCategory
		instance.ObjectMeta.Labels = newlbl
		return true
	}
	if _, ok := instance.ObjectMeta.Labels["category"]; !ok {
		instance.ObjectMeta.Labels["category"] = grcCategory
		return true
	}
	if instance.ObjectMeta.Labels["category"] != grcCategory {
		instance.ObjectMeta.Labels["category"] = grcCategory
		return true
	}
	return false
}

// PeriodicallyExecCertificatePolicies always check status - let this be the only function in the controller
func PeriodicallyExecCertificatePolicies(freq uint, loopflag bool) {
	klog.V(3).Info("PeriodicallyExecCertificatePolicies")
	var plcToUpdateMap map[string]*policyv1.CertificatePolicy
	for {
		start := time.Now()
		printMap(availablePolicies.PolicyMap)

		plcToUpdateMap = make(map[string]*policyv1.CertificatePolicy)

		stateChange := false
		// Loops through all of the cert policies
		for resource, policy := range availablePolicies.PolicyMap {
			namespace := strings.Split(resource, "/")[0]
			klog.V(3).Infof("Checking certificates in namespace %s defined in policy %s", namespace, policy.Name)
			update, nonCompliant, list := checkSecrets(policy, namespace)
			if strings.ToLower(string(policy.Spec.RemediationAction)) == strings.ToLower(string(policyv1.Enforce)) {
				klog.V(3).Infof("Enforce is set, but ignored :-)")
			}
			message := buildPolicyStatusMessage(list, nonCompliant, namespace, policy)

			if addViolationCount(policy, message, nonCompliant, namespace, list) || update {
				plcToUpdateMap[policy.Name] = policy
				stateChange = true
			}

			checkComplianceBasedOnDetails(policy)
			klog.V(3).Infof("Finished processing policy %s, on namespace %s", policy.Name, namespace)
		}

		if stateChange {
			//update status of all policies that changed:
			faultyPlc, err := updatePolicyStatus(plcToUpdateMap)
			if err != nil {
				klog.Errorf("reason: policy update error, subject: policy/%v, namespace: %v, according to policy: %v, additional-info: %v\n", faultyPlc.Name, faultyPlc.Namespace, faultyPlc.Name, err)
			}
		}

		if loopflag {
			//prometheus quantiles for processing delay in each cycle
			elapsed := time.Since(start)
			//making sure that if processing is > freq we don't sleep
			//if freq > processing we sleep for the remaining duration
			elapsed = time.Since(start) / 1000000000 // convert to seconds
			if float64(freq) > float64(elapsed) {
				remainingSleep := float64(freq) - float64(elapsed)
				time.Sleep(time.Duration(remainingSleep) * time.Second)
			}
		} else {
			return
		}
	}
}

// Checks each namespace for certificates that are going to expire within 3 months
// Returns whether a state change is happening, the number of uncompliant certificates and a list of the uncompliant certificates
func checkSecrets(policy *policyv1.CertificatePolicy, namespace string) (bool, uint, map[string]policyv1.Cert) {
	klog.V(3).Info("checkSecrets")
	update := false
	nonCompliantCertificates := make(map[string]policyv1.Cert, 0)
	if namespace == "" {
		return update, uint(len(nonCompliantCertificates)), nonCompliantCertificates
	}
	//TODO: Want the label selector to find secrets with certificates only!! -> is-certificate
	// Loops through all the secrets within the CertificatePolicy's specified namespace
	secretList, _ := (*common.KubeClient).CoreV1().Secrets(namespace).List(metav1.ListOptions{LabelSelector: labels.Set(policy.Spec.LabelSelector).String()})
	for _, secretItem := range secretList.Items {
		secret := secretItem
		klog.V(3).Infof("Checking secret %s", secret.Name)
		cert, err := parseCertificate(&secret)
		if err != nil {
			klog.V(3).Info(err.Error())
		} else if !isCertificateCompliant(cert, policy) {
			certName := secret.Name
			// Gets the certificate's name if it exists
			if secret.Labels[certNameLabel] != "" {
				certName = secret.Labels[certNameLabel]
			} else if secret.Labels[certManagerNameLabel] != "" {
				certName = secret.Labels[certManagerNameLabel]
			}
			msg := fmt.Sprintf("Certificate %s [secret name: %s] is not compliant", certName, secret.ObjectMeta.Name)
			klog.V(3).Info(msg)
			nonCompliantCertificates[certName] = *cert
			if policy.Status.ComplianceState != policyv1.NonCompliant {
				update = true
			}
		}
	}
	return update, uint(len(nonCompliantCertificates)), nonCompliantCertificates
}

// Returns true only if the secret (certificate) is not compliant.
func parseCertificate(secret *corev1.Secret) (*policyv1.Cert, error) {
	var err error
	klog.V(3).Info("checkExpiration")
	keyName := "certificate_key_name"
	key := "tls.crt"
	if secret.Labels != nil && secret.Labels[keyName] != "" {
		key = secret.Labels[keyName]
	}
	klog.V(3).Infof("Checking secret %s with certificate key %s", secret.Name, key)
	// Get the certificate bytes
	certBytes, _ := secret.Data[key]

	var cert policyv1.Cert
	// Get the x509 Certificates
	certs := util.DecodeCertificateBytes(certBytes)
	if len(certs) < 1 {
		msg := fmt.Sprintf("The secret %s does not contain any certificates. Skipping this secret.", secret.Name)
		return nil, errors.New(msg)
	}
	x509Cert := certs[0] // Certificate chains always begin with the end user certificate as a standard format

	// Get time now and subtract from cert's not before
	now := time.Now()
	expiration := x509Cert.NotAfter
	duration := expiration.Sub(now)

	maximumDuration := expiration.Sub(x509Cert.NotBefore)

	cert = policyv1.Cert{
		Secret:     secret.Name,
		Expiration: duration.String(),
		Expiry:     duration,
		CA:         x509Cert.IsCA,
		Duration:   maximumDuration,
		Sans:       x509Cert.DNSNames,
	}

	return &cert, err
}

// Return false if the certificate fails any of the compliance checks
func isCertificateCompliant(cert *policyv1.Cert, policy *policyv1.CertificatePolicy) bool {
	// if the cert is expiring then return false
	flag := isCertificateExpiring(cert, policy)
	if flag {
		return false
	}

	// if the cert has a duration that's too long then return false
	flag = isCertificateLongDuration(cert, policy)
	if flag {
		return false
	}

	// if the SAN pattern doesn't match an entry return false
	flag = isCertificateSANPatternMismatch(cert, policy)
	if flag {
		return false
	}

	return true
}

// isCertificateExpiring return true if the certificate is expired or expiring soon
func isCertificateExpiring(cert *policyv1.Cert, policy *policyv1.CertificatePolicy) bool {
	minimumDuration := DefaultDuration
	policyDuration := policy.Spec.MinDuration
	if policyDuration != nil {
		minimumDuration = policyDuration.Duration
	}

	// Take a look at time left before the cert expires - check for CA scenario first if specified
	minCADuration := policy.Spec.MinCADuration
	if minCADuration != nil && cert.CA {
		if cert.Expiry < minCADuration.Duration {
			return true
		}
	} else {
		if cert.Expiry < minimumDuration {
			return true
		}
	}
	return false
}

// isCertificateLongDuration returns true if the certificate duration is too long
func isCertificateLongDuration(cert *policyv1.Cert, policy *policyv1.CertificatePolicy) bool {
	// Take a look at full certificate duration - check for CA scenario first
	maxCADuration := policy.Spec.MaxCADuration
	maxDuration := policy.Spec.MaxDuration
	if maxCADuration != nil && cert.CA {
		if cert.Duration > maxCADuration.Duration {
			return true
		}
	} else if maxDuration != nil {
		if cert.Duration > maxDuration.Duration {
			return true
		}
	}
	return false
}

// isCertificateSANPatternMatching returns true if the SAN entries don't match the specified pattern
func isCertificateSANPatternMismatch(cert *policyv1.Cert, policy *policyv1.CertificatePolicy) bool {
	// Check SAN entries to validate they match pattern specified
	pattern := policy.Spec.AllowedSANPattern
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			klog.Errorf("The AllowedSANPattern regular expression specified is not valid: %s: Error: %s", pattern, err)
		} else {
			for _, san := range cert.Sans {
				match := re.MatchString(san)
				if !match {
					return true
				}
			}
		}
	}
	// Check SAN entries to validate they do not match the disallowed pattern
	pattern = policy.Spec.DisallowedSANPattern
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			klog.Errorf("The DisallowedSANPattern regular expression specified is not valid: %s: Error: %s", pattern, err)
		} else {
			for _, san := range cert.Sans {
				match := re.MatchString(san)
				if match {
					return true
				}
			}
		}
	}
	return false
}

// buildPolicyStatusMessage returns a message that details the non-compliant status
func buildPolicyStatusMessage(list map[string]policyv1.Cert, count uint, namespace string,
	policy *policyv1.CertificatePolicy) string {

	message := fmt.Sprintf("Found %d non compliant certificates in the namespace %s.\n", count, namespace)
	if namespace == "" {
		message = fmt.Sprintf("Found %d non compliant certificates, no namespaces were selected.\n", count)
	}
	if count > 0 {
		message = fmt.Sprintf("%sList of non compliant certificates:\n", message)
		for cert, certDetails := range list {
			details := certDetails
			if isCertificateExpiring(&details, policy) {
				message = fmt.Sprintf("%s%s expires in %s\n", message, cert, details.Expiration)
			}
			if isCertificateLongDuration(&details, policy) {
				message = fmt.Sprintf("%s%s duration too long %s\n", message, cert, details.Duration.String())
			}
			if isCertificateSANPatternMismatch(&details, policy) {
				pattern := getPatternsUsed(policy)
				message = fmt.Sprintf("%s%s SAN entry found not matching pattern %s\n", message, cert, pattern)
			}
		}
	}

	klog.V(3).Info(message)
	return message
}

func getPatternsUsed(policy *policyv1.CertificatePolicy) string {
	pattern := ""
	if policy.Spec.AllowedSANPattern != "" {
		pattern = fmt.Sprintf("Allowed: %s", policy.Spec.AllowedSANPattern)
	}
	if policy.Spec.DisallowedSANPattern != "" {
		pattern = fmt.Sprintf("%s Disallowed: %s", pattern, policy.Spec.DisallowedSANPattern)
	}
	return pattern
}
func convertMaptoPolicyNameKey() map[string]*policyv1.CertificatePolicy {
	plcMap := make(map[string]*policyv1.CertificatePolicy)
	for _, policy := range availablePolicies.PolicyMap {
		plcMap[policy.Name] = policy
	}
	return plcMap
}

// addViolationCount takes in a certificate policy and updates its status
// with the message passed into this function and the number of certificates
// violated this policy.
func addViolationCount(plc *policyv1.CertificatePolicy, message string, count uint, namespace string, certificates map[string]policyv1.Cert) bool {
	klog.V(3).Info("addViolationCount")
	changed := false
	// Add in default/generic message that can be overridden
	msg := fmt.Sprintf("%s violations detected in namespace `%s`", fmt.Sprint(count), namespace)
	if message != "" {
		msg = message
	}

	if plc.Status.CompliancyDetails == nil {
		plc.Status.CompliancyDetails = make(map[string]policyv1.CompliancyDetails)
	}
	if _, ok := plc.Status.CompliancyDetails[namespace]; !ok {
		changed = true
	}

	if count == 0 && plc.Status.ComplianceState == policyv1.NonCompliant {
		changed = true
	}
	// The number of non-compliant certificates has changed, so change the overall compliance state
	if plc.Status.CompliancyDetails[namespace].NonCompliantCertificates != count {
		changed = true
	}
	if count > 0 && plc.Status.ComplianceState == policyv1.Compliant {
		changed = true
	}
	if message != plc.Status.CompliancyDetails[namespace].Message {
		changed = true
	}
	// TODO: I think we need to compare certificates and set changed = true if we detect changes
	plc.Status.CompliancyDetails[namespace] = policyv1.CompliancyDetails{
		NonCompliantCertificates:     count,
		NonCompliantCertificatesList: certificates,
		Message:                      msg,
	}
	klog.Infof("The policy %s has been updated with the message: %s", plc.Name, msg)
	return changed
}

// checkComplianceBasedOnDetails takes a certificate and sets whether
// the policy is compliant or not based on the certificate's status
func checkComplianceBasedOnDetails(plc *policyv1.CertificatePolicy) {
	klog.V(3).Info("checkComplianceBasedOnDetails")
	plc.Status.ComplianceState = policyv1.Compliant
	if plc.Status.CompliancyDetails == nil {
		return
	}
	if len(plc.Status.CompliancyDetails) == 0 {
		return
	}
	for namespace, details := range plc.Status.CompliancyDetails {
		if details.NonCompliantCertificates > 0 {
			klog.Infof("The number of violations in policy %s in namespace %s does not equal zero, therefore it is non compliant", plc.Name, namespace)
			plc.Status.ComplianceState = policyv1.NonCompliant
		}
	}
}

func checkComplianceChangeBasedOnDetails(plc *policyv1.CertificatePolicy) (complianceChanged bool) {
	klog.V(3).Info("checkComplianceChangeBasedOnDetails")
	//used in case we also want to know not just the compliance state, but also whether the compliance changed or not.
	previous := plc.Status.ComplianceState
	if plc.Status.CompliancyDetails == nil {
		plc.Status.ComplianceState = policyv1.UnknownCompliancy
		return reflect.DeepEqual(previous, plc.Status.ComplianceState)
	}
	if plc.Status.CompliancyDetails == nil {
		plc.Status.ComplianceState = policyv1.UnknownCompliancy
		return reflect.DeepEqual(previous, plc.Status.ComplianceState)
	}
	if len(plc.Status.CompliancyDetails) == 0 {
		plc.Status.ComplianceState = policyv1.UnknownCompliancy
		return reflect.DeepEqual(previous, plc.Status.ComplianceState)
	}
	plc.Status.ComplianceState = policyv1.Compliant
	for _, details := range plc.Status.CompliancyDetails {
		if details.NonCompliantCertificates > 0 {
			plc.Status.ComplianceState = policyv1.NonCompliant
		} else {
			return reflect.DeepEqual(previous, plc.Status.ComplianceState)
		}
	}
	if plc.Status.ComplianceState != policyv1.NonCompliant {
		plc.Status.ComplianceState = policyv1.Compliant
	}
	return reflect.DeepEqual(previous, plc.Status.ComplianceState)
}

func updatePolicyStatus(policies map[string]*policyv1.CertificatePolicy) (*policyv1.CertificatePolicy, error) {
	klog.V(3).Info("Updating the Policy Status")
	for _, instance := range policies { // policies is a map where: key = plc.Name, value = pointer to plc
		klog.V(3).Infof("Updating the Policy Status %s namespace %s, %s.%s", instance.Name, instance.Namespace, instance.Kind, instance.APIVersion)
		err := reconcilingAgent.client.Status().Update(context.TODO(), instance)
		if err != nil {
			return instance, err
		}
		if EventOnParent != "no" {
			createParentPolicyEvent(instance)
		}
		message := fmt.Sprintf("%v", instance.Status.ComplianceState)
		klog.V(3).Infof("Policy %s Compliance State %s", instance.Name, message)
		for namespace, details := range instance.Status.CompliancyDetails {
			if details.NonCompliantCertificates > 0 {

				message = fmt.Sprintf("%s; Non-compliant certificates in %s[%d]:",
					message, namespace, details.NonCompliantCertificates)
				for cert, certDetails := range details.NonCompliantCertificatesList {
					message = fmt.Sprintf("%s [%s, %s]", message, cert, certDetails.Secret)
				}
				klog.V(3).Infof("Noncompliant certs %d %s", details.NonCompliantCertificates, message)
			}
		}
		if reconcilingAgent.recorder != nil {
			if instance.Status.ComplianceState == policyv1.NonCompliant {
				reconcilingAgent.recorder.Event(instance, corev1.EventTypeWarning, "Policy updated", message)
			} else {
				reconcilingAgent.recorder.Event(instance, corev1.EventTypeNormal, "Policy updated", message)
			}
		}
	}
	return nil, nil
}

func handleRemovingPolicy(name string) {
	klog.V(3).Info("handleRemovingPolicy")
	for k, v := range availablePolicies.PolicyMap {
		if v.Name == name {
			availablePolicies.RemoveObject(k)
		}
	}
}

func handleAddingPolicy(plc *policyv1.CertificatePolicy) error {
	klog.V(3).Info("handleAddingPolicy")
	allNamespaces, err := common.GetAllNamespaces()
	if err != nil {

		klog.Errorf("reason: error fetching the list of available namespaces, subject: K8s API server, namespace: all, according to policy: %v, additional-info: %v\n", plc.Name, err)

		return err
	}
	//clean up that policy from the existing namepsaces, in case the modification is in the namespace selector
	for _, ns := range allNamespaces {
		cleanupAvailablePolicies(ns, plc.Name)
	}
	cleanupAvailablePolicies("", plc.Name)
	var addFlag = false
	selectedNamespaces := common.GetSelectedNamespaces(plc.Spec.NamespaceSelector.Include, plc.Spec.NamespaceSelector.Exclude, allNamespaces)
	for _, ns := range selectedNamespaces {
		key := fmt.Sprintf("%s/%s", ns, plc.Name)
		availablePolicies.AddObject(key, plc)
		addFlag = true
	}
	if addFlag == false {
		key := fmt.Sprintf("/%s", plc.Name)
		availablePolicies.AddObject(key, plc)
	}
	return err
}

func cleanupAvailablePolicies(namespace string, name string) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	if policy, found := availablePolicies.GetObject(key); found {
		if policy.Name == name {
			availablePolicies.RemoveObject(key)
		}
	}
}

//=================================================================
// Helper functions that pretty prints a map
func printMap(myMap map[string]*policyv1.CertificatePolicy) {
	if len(myMap) == 0 {
		fmt.Println("Waiting for policies to be available for processing... ")
		return
	}
	fmt.Println("Available policies in namespaces: ")

	for k, v := range myMap {
		fmt.Printf("namespace = %v; policy = %v \n", k, v.Name)
	}
}

func createParentPolicyEvent(instance *policyv1.CertificatePolicy) {
	klog.V(3).Info("createParentPolicyEvent")
	if len(instance.OwnerReferences) == 0 {
		return //there is nothing to do, since no owner is set
	}
	// we are making an assumption that the Certificate policy has a single owner, or we chose the first owner in the list
	if string(instance.OwnerReferences[0].UID) == "" {
		return //there is nothing to do, since no owner UID is set
	}

	parentPlc := createParentPolicy(instance)
	if reconcilingAgent.recorder != nil {
		if instance.Status.ComplianceState == policyv1.NonCompliant {
			klog.V(3).Info("Update parent policy, non-compliant policy")
			reconcilingAgent.recorder.Event(&parentPlc, corev1.EventTypeWarning, fmt.Sprintf("policy: %s/%s", instance.Namespace, instance.Name), convertPolicyStatusToString(instance, DefaultDuration))
		} else {
			klog.V(3).Info("Update parent policy, compliant policy")
			reconcilingAgent.recorder.Event(&parentPlc, corev1.EventTypeNormal, fmt.Sprintf("policy: %s/%s", instance.Namespace, instance.Name), convertPolicyStatusToString(instance, DefaultDuration))
		}
	}
}

func createParentPolicy(instance *policyv1.CertificatePolicy) policyv1.Policy {
	klog.V(3).Info("createParentPolicy")
	ns := common.ExtractNamespaceLabel(instance)
	if ns == "" {
		ns = NamespaceWatched
	}
	plc := policyv1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.OwnerReferences[0].Name,
			Namespace: ns, // we are making an assumption here that the parent policy is in the watched-namespace passed as flag
			UID:       instance.OwnerReferences[0].UID,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policy.open-cluster-management.io/v1",
		},
	}
	return plc
}
