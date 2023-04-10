// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	extpolicyv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1 "open-cluster-management.io/cert-policy-controller/api/v1"
	"open-cluster-management.io/cert-policy-controller/controllers/util"
	"open-cluster-management.io/cert-policy-controller/pkg/common"
)

const (
	certNameLabel        = "certificate-name"
	certManagerNameLabel = "certmanager.k8s.io/certificate-name"
	ControllerName       = "certificate-policy-controller"
)

var (
	// availablePolicies is a cache of all available polices.
	availablePolicies common.SyncedPolicyMap
	// PlcChan a channel used to pass policies ready for update.
	PlcChan chan *policyv1.CertificatePolicy
	// NamespaceWatched defines which namespace we can watch for the Certificate policies and ignore others.
	NamespaceWatched string
	// EventOnParent specifies if we also want to send events to the parent policy. Available options are yes/no/ifpresent.
	EventOnParent string
	// DefaultDuration is the default minimum duration (if one isn't specified in a policy) that a certificate can be valid
	// for to be compliant.
	DefaultDuration time.Duration
)

var log = ctrl.Log.WithName(ControllerName)

// Initialize to initialize some controller variables.
func (r *CertificatePolicyReconciler) Initialize(namespace, eventParent string,
	defaultDuration time.Duration,
) (err error) {
	PlcChan = make(chan *policyv1.CertificatePolicy, 100) // buffering up to 100 policies for update

	NamespaceWatched = namespace

	EventOnParent = strings.ToLower(eventParent)

	DefaultDuration = defaultDuration

	return nil
}

var _ reconcile.Reconciler = &CertificatePolicyReconciler{}

// Reconciler reconciles a CertificatePolicy object.
type CertificatePolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	// The Kubernetes client to use when evaluating/enforcing policies. Most times,
	// this will be the same cluster where the controller is running.
	TargetK8sClient kubernetes.Interface
	TargetK8sConfig *rest.Config
}

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=certificatepolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=certificatepolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=certificatepolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=list
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.9.2/pkg/reconcile
func (r *CertificatePolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling CertificatePolicy")

	// Fetch the CertificatePolicy instance
	instance := &policyv1.CertificatePolicy{}

	err := r.Get(ctx, request.NamespacedName, instance)
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
		instance.Status.CompliancyDetails = make(map[string]policyv1.CompliancyDetails)

		r.handleAddingPolicy(instance)
	}

	reqLogger.V(1).Info("Successful processing", "instance.Name", instance.Name, "instance.Namespace",
		instance.Namespace)

	return reconcile.Result{}, nil
}

// PeriodicallyExecCertificatePolicies always check status - let this be the only function in the controller.
func (r *CertificatePolicyReconciler) PeriodicallyExecCertificatePolicies(freq uint, loopflag bool) {
	log.V(3).Info("Entered PeriodicallyExecCertificatePolicies")
	var plcToUpdateMap map[string]*policyv1.CertificatePolicy

	for {
		start := time.Now()

		printMap(availablePolicies.PolicyMap)

		plcToUpdateMap = make(map[string]*policyv1.CertificatePolicy)

		stateChange := r.ProcessPolicies(plcToUpdateMap)

		if stateChange {
			// update status of all policies that changed:
			faultyPlc, err := r.updatePolicyStatus(plcToUpdateMap)
			if err != nil {
				log.Error(err, "Unable to update policy status", "Name", faultyPlc.Name, "Namespace",
					faultyPlc.Namespace)
			}
		}

		if loopflag {
			// prometheus quantiles for processing delay in each cycle
			// making sure that if processing is > freq we don't sleep
			// if freq > processing we sleep for the remaining duration
			elapsed := time.Since(start) / 1000000000 // convert to seconds
			if float64(freq) > float64(elapsed) {
				remainingSleep := float64(freq) - float64(elapsed)
				time.Sleep(time.Duration(remainingSleep) * time.Second)
			}
		} else {
			return
		}
	}
}

// ProcessPolicies reads each policy and looks for violations returning true if a change is found.
func (r *CertificatePolicyReconciler) ProcessPolicies(plcToUpdateMap map[string]*policyv1.CertificatePolicy) bool {
	stateChange := false

	plcMap := make(map[string]*policyv1.CertificatePolicy)
	// create a map of all policies
	for _, policy := range availablePolicies.PolicyMap {
		plcMap[policy.Name] = policy
	}
	// update available policies if there are changed namespaces
	for _, plc := range plcMap {
		// Retrieve the namespaces based on filters in NamespaceSelector
		selectedNamespaces := r.retrieveNamespaces(plc.Spec.NamespaceSelector)

		// add availablePolicy if not present
		for _, ns := range selectedNamespaces {
			key := fmt.Sprintf("%s/%s", ns, plc.Name)
			_, found := availablePolicies.GetObject(key)

			if !found {
				availablePolicies.AddObject(key, plc)
				plcToUpdateMap[plc.Name] = plc
				// remove the dummy entry not matching namespaces if it exists
				cleanupAvailablePolicies("", plc.Name)
			}
		}

		handleNamespaceRemovals(plc, plcToUpdateMap, selectedNamespaces)

		if len(selectedNamespaces) == 0 {
			// add a dummy entry to force updates when no namespaces match
			key := fmt.Sprintf("/%s", plc.Name)
			_, found := availablePolicies.GetObject(key)

			if !found {
				availablePolicies.AddObject(key, plc)
				plcToUpdateMap[plc.Name] = plc
			}
		}
	}

	if len(plcToUpdateMap) > 0 {
		stateChange = true
	}

	// Loops through all of the cert policies looking for violations
	for key, policy := range availablePolicies.PolicyMap {
		namespace := strings.Split(key, "/")[0]

		log.V(2).Info("Checking certificates", "namespace", namespace, "policy.Name", policy.Name)

		update, nonCompliant, list := r.checkSecrets(policy, namespace)

		if strings.EqualFold(string(policy.Spec.RemediationAction), string(policyv1.Enforce)) {
			log.V(1).Info("Enforce is set, but not implemented on this controller")
		}

		message := buildPolicyStatusMessage(list, nonCompliant, namespace, policy)

		countUpdated := addViolationCount(policy, message, nonCompliant, namespace, list)
		if countUpdated || update {
			plcToUpdateMap[policy.Name] = policy
		}

		if countUpdated {
			stateChange = true
		}

		log.V(3).Info("Finished processing policy", "name", policy.Name, "namespace", namespace,
			"countUpdated", countUpdated, "update", update, "stateChange", stateChange, "state",
			policy.Status.ComplianceState)
	}

	for _, policy := range plcMap {
		// need to see if we change from noncompliant to compliant
		currentStatus := policy.Status.ComplianceState
		checkComplianceBasedOnDetails(policy)
		log.V(1).Info("Got compliance", "policy.Name", policy.Name, "state", policy.Status.ComplianceState)

		if currentStatus != policy.Status.ComplianceState {
			stateChange = true
		}
	}

	return stateChange
}

// handleNamespaceRemovals make sure policies get updated for cases where a namespace has been removed.
func handleNamespaceRemovals(policy *policyv1.CertificatePolicy,
	plcToUpdateMap map[string]*policyv1.CertificatePolicy, selectedNamespaces []string,
) {
	for key, plc := range availablePolicies.PolicyMap {
		namespace := strings.Split(key, "/")[0]

		if plc.Name == policy.Name {
			found := false

			for _, ns := range selectedNamespaces {
				if ns == namespace {
					found = true

					break
				}
			}

			if !found {
				// the namespace was not found, clean up
				cleanupAvailablePolicies(namespace, policy.Name)
				plcToUpdateMap[policy.Name] = policy
			}
		}
	}
}

// toLabelSet converts a map of NonEmptyStrings to a Kubernetes label set.
func toLabelSet(v map[string]policyv1.NonEmptyString) labels.Set {
	labelSelector := labels.Set{}
	for key, val := range v {
		labelSelector[key] = string(val)
	}

	return labelSelector
}

// Checks each namespace for certificates that are going to expire within 3 months
// Returns whether a state change is happening, the number of uncompliant certificates
// and a list of the uncompliant certificates.
func (r *CertificatePolicyReconciler) checkSecrets(policy *policyv1.CertificatePolicy,
	namespace string,
) (bool, uint, map[string]policyv1.Cert) {
	slog := log.WithValues("policy.Namespace", policy.Namespace, "policy.Name", policy.Name)
	slog.V(3).Info("Entered checkSecrets")

	update := false
	nonCompliantCertificates := make(map[string]policyv1.Cert)

	if namespace == "" {
		return update, uint(len(nonCompliantCertificates)), nonCompliantCertificates
	}
	// GOAL: Want the label selector to find secrets with certificates only!! -> is-certificate
	// Loops through all the secrets within the CertificatePolicy's specified namespace
	labelSelector := toLabelSet(policy.Spec.LabelSelector)
	secretList, _ := r.TargetK8sClient.CoreV1().Secrets(namespace).List(context.TODO(),
		metav1.ListOptions{LabelSelector: labelSelector.String()})

	for _, secretItem := range secretList.Items {
		secret := secretItem
		slog.V(3).Info("Checking secret", "secret.Name", secret.Name)

		cert, err := parseCertificate(&secret)
		if err != nil {
			slog.Error(err, "Unable to parse certificate", "secret.Name", secret.Name)
		} else if !isCertificateCompliant(cert, policy) {
			certName := secret.Name
			// Gets the certificate's name if it exists
			if secret.Labels[certNameLabel] != "" {
				certName = secret.Labels[certNameLabel]
			} else if secret.Labels[certManagerNameLabel] != "" {
				certName = secret.Labels[certManagerNameLabel]
			}
			slog.V(3).Info("Got noncompliant certifiate", "certName", certName, "secret.Name", secret.Name)
			nonCompliantCertificates[certName] = *cert
			if policy.Status.ComplianceState != policyv1.NonCompliant {
				update = true
			}
		}
	}

	return update, uint(len(nonCompliantCertificates)), nonCompliantCertificates
}

func (r *CertificatePolicyReconciler) retrieveNamespaces(selector policyv1.Target) []string {
	var selectedNamespaces []string
	// If MatchLabels/MatchExpressions/Include were not provided, return no namespaces
	if selector.MatchLabels == nil && selector.MatchExpressions == nil && len(selector.Include) == 0 {
		log.Info("NamespaceSelector is empty. Skipping namespace retrieval.")
	} else {
		var err error
		selectedNamespaces, err = common.GetSelectedNamespaces(r.TargetK8sClient, selector)
		if err != nil {
			log.Error(
				err, "Error filtering namespaces with provided NamespaceSelector",
				"namespaceSelector", fmt.Sprintf("%+v", selector))
		}
	}

	return selectedNamespaces
}

// Returns true only if the secret (certificate) is not compliant.
func parseCertificate(secret *corev1.Secret) (*policyv1.Cert, error) {
	log.V(3).Info("entered parseCertificate")

	keyName := "certificate_key_name"
	key := "tls.crt"

	if secret.Labels != nil && secret.Labels[keyName] != "" {
		key = secret.Labels[keyName]
	}

	log.V(3).Info("Checking secret", "secret.Name", secret.Name, "certificateKey", key)
	// Get the certificate bytes
	certBytes := secret.Data[key]

	var cert policyv1.Cert
	// Get the x509 Certificates
	certs, err := util.DecodeCertificateBytes(certBytes)
	if err != nil {
		log.Error(err, "Error decoding a certificate in the secret; ignoring this error")
	}

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

	return &cert, nil
}

// Return false if the certificate fails any of the compliance checks.
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
	return !isCertificateSANPatternMismatch(cert, policy)
}

// isCertificateExpiring return true if the certificate is expired or expiring soon.
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

// isCertificateLongDuration returns true if the certificate duration is too long.
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

// isCertificateSANPatternMatching returns true if the SAN entries don't match the specified pattern.
func isCertificateSANPatternMismatch(cert *policyv1.Cert, policy *policyv1.CertificatePolicy) bool {
	// Check SAN entries to validate they match pattern specified
	pattern := policy.Spec.AllowedSANPattern
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Error(err, "The AllowedSANPattern regular expression specified is not valid", "pattern", pattern)
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
			log.Error(err, "The DisallowedSANPattern regular expression specified is not valid", "pattern", pattern)
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

// buildPolicyStatusMessage returns a message that details the non-compliant status.
func buildPolicyStatusMessage(list map[string]policyv1.Cert, count uint, namespace string,
	policy *policyv1.CertificatePolicy,
) string {
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

	log.V(3).Info("Built status message", "message", message, "policy.Name", policy.Name,
		"policy.Namespace", policy.Namespace)

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

// addViolationCount takes in a certificate policy and updates its status
// with the message passed into this function and the number of certificates
// violated this policy.
func addViolationCount(plc *policyv1.CertificatePolicy, message string, count uint, namespace string,
	certificates map[string]policyv1.Cert,
) bool {
	log.V(3).Info("Entered addViolationCount")

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

	// Do not flag the following as a state change since some namespaces could be NonCompliant so
	// we don't want a compliant namespace in the same policy to falsely set changed as true
	//if count == 0 && plc.Status.ComplianceState == policyv1.NonCompliant {
	//	changed = true
	//}

	// The number of non-compliant certificates has changed, so change the overall compliance state
	if plc.Status.CompliancyDetails[namespace].NonCompliantCertificates != count {
		changed = true
	}
	// this is a clear change in state so the multiple namespace concern doesn't apply here
	if count > 0 && plc.Status.ComplianceState == policyv1.Compliant {
		changed = true
	}
	// The message contains the amount of time until expiration which changes each cycle
	// Do not compare the message
	//if msg != plc.Status.CompliancyDetails[namespace].Message {
	//	klog.Infof("The policy %s has a new message: %s", plc.Name, msg)
	//	changed = true
	//}
	if haveNewNonCompliantCertificate(plc, namespace, certificates) {
		changed = true
	}

	plc.Status.CompliancyDetails[namespace] = policyv1.CompliancyDetails{
		NonCompliantCertificates:     count,
		NonCompliantCertificatesList: certificates,
		Message:                      msg,
	}
	log.Info("Policy updated", "policy.Name", plc.Name, "message", msg)

	return changed
}

// haveNewNonCompliantCertificate returns true if a new certificate needs to be added
// to the list of certificates that are not compliant.
func haveNewNonCompliantCertificate(plc *policyv1.CertificatePolicy, namespace string,
	certificates map[string]policyv1.Cert,
) bool {
	result := false

	for name := range certificates {
		found := false

		for existing := range plc.Status.CompliancyDetails[namespace].NonCompliantCertificatesList {
			if name == existing {
				found = true

				break
			}
		}

		if !found {
			// we can stop now
			result = true

			break
		}
	}

	return result
}

// checkComplianceBasedOnDetails takes a certificate and sets whether
// the policy is compliant or not based on the certificate's status.
func checkComplianceBasedOnDetails(plc *policyv1.CertificatePolicy) {
	log.V(3).Info("Entered checkComplianceBasedOnDetails")

	plc.Status.ComplianceState = policyv1.Compliant

	if plc.Status.CompliancyDetails == nil {
		return
	}

	if len(plc.Status.CompliancyDetails) == 0 {
		return
	}

	for namespace, details := range plc.Status.CompliancyDetails {
		if details.NonCompliantCertificates > 0 {
			log.Info("Policy has violations and is non compliant", "plc.Name", plc.Name, "namespace", namespace)

			plc.Status.ComplianceState = policyv1.NonCompliant
		}
	}
}

func checkComplianceChangeBasedOnDetails(plc *policyv1.CertificatePolicy) (complianceChanged bool) {
	log.V(3).Info("Entered checkComplianceChangeBasedOnDetails")
	// used in case we also want to know not just the compliance state, but also whether the compliance changed or not.
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

func (r *CertificatePolicyReconciler) updatePolicyStatus(policies map[string]*policyv1.CertificatePolicy,
) (*policyv1.CertificatePolicy, error) {
	log.V(3).Info("Entered updatePolicyStatus")

	for _, instance := range policies { // policies is a map where: key = plc.Name, value = pointer to plc
		ilog := log.WithValues("instance.Namespace", instance.Namespace, "instance.Name", instance.Name)
		ilog.V(3).Info("Updating the Policy Status")

		message := fmt.Sprintf("%v", instance.Status.ComplianceState)
		ilog.V(3).Info("Got Compliance State", "state", message)

		for namespace, details := range instance.Status.CompliancyDetails {
			if details.NonCompliantCertificates > 0 {
				message = fmt.Sprintf("%s; Non-compliant certificates in %s[%d]:",
					message, namespace, details.NonCompliantCertificates)
				for cert, certDetails := range details.NonCompliantCertificatesList {
					message = fmt.Sprintf("%s [%s, %s]", message, cert, certDetails.Secret)
				}

				ilog.V(3).Info("Found non compliant certs", "count", details.NonCompliantCertificates,
					"message", message)
			}
		}

		err := r.Status().Update(context.TODO(), instance)
		if err != nil {
			return instance, err
		}

		if EventOnParent != "no" {
			r.createParentPolicyEvent(instance)
		}

		if r.Recorder != nil {
			if instance.Status.ComplianceState == policyv1.NonCompliant {
				r.Recorder.Event(instance, corev1.EventTypeWarning, "Policy updated", message)
			} else {
				r.Recorder.Event(instance, corev1.EventTypeNormal, "Policy updated", message)
			}
		}
	}

	return nil, nil
}

func handleRemovingPolicy(name string) {
	log.V(3).Info("Entered handleRemovingPolicy")

	for k, v := range availablePolicies.PolicyMap {
		if v.Name == name {
			availablePolicies.RemoveObject(k)
		}
	}
}

func (r *CertificatePolicyReconciler) handleAddingPolicy(plc *policyv1.CertificatePolicy) {
	log.V(3).Info("Entered handleAddingPolicy")

	// clean up that policy from the availablePolicies list, in case the modification is in the
	// namespace selector
	for key, policy := range availablePolicies.PolicyMap {
		if policy.Name == plc.Name {
			availablePolicies.RemoveObject(key)
		}
	}

	cleanupAvailablePolicies("", plc.Name)

	addFlag := false

	// Retrieve the namespaces based on filters in NamespaceSelector
	selectedNamespaces := r.retrieveNamespaces(plc.Spec.NamespaceSelector)

	for _, ns := range selectedNamespaces {
		key := fmt.Sprintf("%s/%s", ns, plc.Name)
		availablePolicies.AddObject(key, plc)

		addFlag = true
	}

	if !addFlag {
		key := fmt.Sprintf("/%s", plc.Name)
		availablePolicies.AddObject(key, plc)
	}
}

func cleanupAvailablePolicies(namespace string, name string) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	if policy, found := availablePolicies.GetObject(key); found {
		if policy.Name == name {
			availablePolicies.RemoveObject(key)

			if policy.Status.CompliancyDetails != nil {
				delete(policy.Status.CompliancyDetails, namespace)
			}
		}
	}
}

// =================================================================
// Helper functions that pretty prints a map.
func printMap(myMap map[string]*policyv1.CertificatePolicy) {
	if len(myMap) == 0 {
		log.Info("Waiting for policies to be available for processing...")

		return
	}

	log.Info("Available policies in namespaces:")

	for k, v := range myMap {
		log.Info("-", "namespace", k, "policy", v.Name)
	}
}

func (r *CertificatePolicyReconciler) createParentPolicyEvent(instance *policyv1.CertificatePolicy) {
	ilog := log.WithValues("instance.Namespace", instance.Namespace, "instance.Name", instance.Name)
	ilog.V(3).Info("Entered createParentPolicyEvent")

	if len(instance.OwnerReferences) == 0 {
		return // there is nothing to do, since no owner is set
	}
	// Assumes the Certificate policy has a single owner, or we chose the first owner in the list
	if string(instance.OwnerReferences[0].UID) == "" {
		return // there is nothing to do, since no owner UID is set
	}

	parentPlc := createParentPolicy(instance)

	if r.Recorder != nil {
		if instance.Status.ComplianceState == policyv1.NonCompliant {
			ilog.V(3).Info("Update parent policy, non-compliant policy")
			r.Recorder.Event(&parentPlc, corev1.EventTypeWarning, fmt.Sprintf("policy: %s/%s",
				instance.Namespace, instance.Name),
				convertPolicyStatusToString(instance, DefaultDuration))
		} else {
			ilog.V(3).Info("Update parent policy, compliant policy")
			r.Recorder.Event(&parentPlc, corev1.EventTypeNormal, fmt.Sprintf("policy: %s/%s",
				instance.Namespace, instance.Name),
				convertPolicyStatusToString(instance, DefaultDuration))
		}
	}
}

func createParentPolicy(instance *policyv1.CertificatePolicy) extpolicyv1.Policy {
	log.V(3).Info("Entered createParentPolicy")

	plc := extpolicyv1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name: instance.OwnerReferences[0].Name,
			// It's assumed that the parent policy is in the same namespace as the cert policy
			Namespace: instance.Namespace,
			UID:       instance.OwnerReferences[0].UID,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policy.open-cluster-management.io/v1",
		},
	}

	return plc
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificatePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&policyv1.CertificatePolicy{}).
		Complete(r)
}
