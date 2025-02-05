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
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
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
	// EventOnParent specifies if we also want to send events to the parent policy. Available options are yes/no/ifpresent.
	EventOnParent string
	// DefaultDuration is the default minimum duration (if one isn't specified in a policy) that a certificate can be valid
	// for to be compliant.
	DefaultDuration time.Duration
)

var log = ctrl.Log.WithName(ControllerName)

// Initialize to initialize some controller variables.
func (r *CertificatePolicyReconciler) Initialize(eventParent string, defaultDuration time.Duration) (err error) {
	EventOnParent = strings.ToLower(eventParent)

	DefaultDuration = defaultDuration

	return nil
}

var _ reconcile.Reconciler = &CertificatePolicyReconciler{}

// Reconciler reconciles a CertificatePolicy object.
type CertificatePolicyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	InstanceName string
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

// Reconcile only runs on DeleteFunc since this controller is polling based.
func (r *CertificatePolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := log.WithValues("name", request.Name, "namespace", request.Namespace)
	policy := &policyv1.CertificatePolicy{}

	err := r.Get(ctx, request.NamespacedName, policy)
	if !k8serrors.IsNotFound(err) {
		log.V(1).Info(fmt.Sprintf("Failure while fetching deleted policy. Re-reconciling: %s", err.Error()))

		return reconcile.Result{}, err
	}

	log.V(1).Info("Handling a deleted policy")
	removeCertPolicyMetrics(request)

	return reconcile.Result{}, nil
}

// PeriodicallyExecCertificatePolicies always check status - let this be the
// only function in the controller. Accepts a context, duration for each loop
// iteration, and a boolean to shut off the loop (for testing scenarios).
func (r *CertificatePolicyReconciler) PeriodicallyExecCertificatePolicies(
	ctx context.Context, freq uint, loopflag bool,
) {
	log.V(3).Info("Entered PeriodicallyExecCertificatePolicies")

	for {
		start := time.Now()

		policies := policyv1.CertificatePolicyList{}

		err := r.List(ctx, &policies)
		if err != nil {
			log.Error(err, "Failed to list policies")

			if !loopflag {
				return
			}

			// Wait if the loop duration hasn't passed yet
			loopWait(start, float64(freq))

			continue
		}

		updatedPolicies := r.ProcessPolicies(ctx, &policies)

		if len(updatedPolicies) > 0 {
			// update status of all policies that changed:
			faultyPlc, err := r.updatePolicyStatus(ctx, updatedPolicies)
			if err != nil {
				log.Error(err, "Unable to update policy status", "Name", faultyPlc.Name, "Namespace",
					faultyPlc.Namespace)
			}
		}

		if !loopflag {
			return
		}

		policyTotalEvalSecondsCounter.Observe(time.Since(start).Seconds())

		// Wait if the loop duration hasn't passed yet
		loopWait(start, float64(freq))
	}
}

// loopWait calculates whether the configured duration has passed since the
// start of the loop iteration. If it hasn't, it sleeps until the duration has
// passed.
func loopWait(start time.Time, freq float64) {
	elapsed := time.Since(start).Seconds()
	if freq > elapsed {
		remainingSleep := freq - elapsed
		time.Sleep(time.Duration(remainingSleep) * time.Second)
	}
}

// ProcessPolicies reads each policy and looks for violations returning true if a change is found.
func (r *CertificatePolicyReconciler) ProcessPolicies(
	ctx context.Context, policies *policyv1.CertificatePolicyList,
) []*policyv1.CertificatePolicy {
	updatedPolicies := map[types.NamespacedName]*policyv1.CertificatePolicy{}

	// update available policies if there are changed namespaces
	for i := range policies.Items {
		evalStart := time.Now().UTC()
		policy := policies.Items[i]

		namespacedName := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}

		log.Info("Checking certificates", "policy.Name", policy.Name)

		// Retrieve the namespaces based on filters in NamespaceSelector
		selectedNamespaces := r.retrieveNamespaces(ctx, policy.Spec.NamespaceSelector)

		// If there are no applicable namespaces, make the policy compliant
		if len(selectedNamespaces) == 0 {
			selectedNamespaces = []string{""}
		}

		processedNamespaces := make(map[string]bool, len(selectedNamespaces))

		for _, namespace := range selectedNamespaces {
			log.V(2).Info("Checking certificates", "namespace", namespace, "policy.Name", policy.Name)

			processedNamespaces[namespace] = true

			update, nonCompliant, list := r.checkSecrets(ctx, &policy, namespace)

			message := buildPolicyStatusMessage(list, nonCompliant, namespace, &policy)

			countUpdated := addViolationCount(&policy, message, nonCompliant, namespace, list)
			if countUpdated || update {
				updatedPolicies[namespacedName] = &policy
			}

			log.V(3).Info("Finished processing policy for namespace", "name", policy.Name, "namespace", namespace,
				"countUpdated", countUpdated, "update", update, "state", policy.Status.ComplianceState)
		}

		// Remove no longer selected namespaces
		for existingNamespace := range policy.Status.CompliancyDetails {
			if !processedNamespaces[existingNamespace] {
				delete(policy.Status.CompliancyDetails, existingNamespace)
				updatedPolicies[namespacedName] = &policy
			}
		}

		// need to see if we change from noncompliant to compliant
		checkComplianceBasedOnDetails(&policy)

		log.V(1).Info("Got compliance", "policy.Name", policy.Name, "state", policy.Status.ComplianceState)

		certPolicyStatusGauge.WithLabelValues(
			policy.Name, policy.Namespace,
		).Set(
			getStatusValue(policy.Status.ComplianceState),
		)
		policyEvalSecondsCounter.WithLabelValues(policy.Name).Add(time.Now().UTC().Sub(evalStart).Seconds())
		policyEvalCounter.WithLabelValues(policy.Name).Inc()
	}

	rv := make([]*policyv1.CertificatePolicy, 0, len(updatedPolicies))

	for _, policy := range updatedPolicies {
		rv = append(rv, policy)
	}

	return rv
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
func (r *CertificatePolicyReconciler) checkSecrets(ctx context.Context, policy *policyv1.CertificatePolicy,
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
	secretList, _ := r.TargetK8sClient.CoreV1().Secrets(namespace).List(ctx,
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

func (r *CertificatePolicyReconciler) retrieveNamespaces(ctx context.Context, selector policyv1.Target) []string {
	var selectedNamespaces []string
	// If MatchLabels/MatchExpressions/Include were not provided, return no namespaces
	if selector.MatchLabels == nil && selector.MatchExpressions == nil && len(selector.Include) == 0 {
		log.Info("NamespaceSelector is empty. Skipping namespace retrieval.")
	} else {
		var err error
		selectedNamespaces, err = common.GetSelectedNamespaces(ctx, r.TargetK8sClient, selector)
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
		Expiration: expiration.UTC().Format(time.RFC3339),
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
				message = fmt.Sprintf("%s%s expires on %s\n", message, cert, details.Expiration)
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
	msg := fmt.Sprintf("%d violations detected in namespace `%s`", count, namespace)
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

	if msg != plc.Status.CompliancyDetails[namespace].Message {
		changed = true
	}

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

func (r *CertificatePolicyReconciler) updatePolicyStatus(
	ctx context.Context, policies []*policyv1.CertificatePolicy,
) (*policyv1.CertificatePolicy, error) {
	log.V(3).Info("Entered updatePolicyStatus")

	for _, instance := range policies {
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

		err := r.sendComplianceEvent(ctx, instance)
		if err != nil {
			return instance, err
		}

		// next do the status update
		err = r.Status().Update(ctx, instance)
		if err != nil {
			return instance, err
		}

		if r.Recorder != nil {
			eType := "Normal"
			if instance.Status.ComplianceState == policyv1.NonCompliant {
				eType = "Warning"
			}

			r.Recorder.Event(instance, eType, "Policy updated", message)
		}
	}

	return nil, nil
}

func (r *CertificatePolicyReconciler) sendComplianceEvent(ctx context.Context,
	instance *policyv1.CertificatePolicy,
) error {
	if len(instance.OwnerReferences) == 0 {
		return nil // there is nothing to do, since no owner is set
	}

	now := time.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			// This event name matches the convention of recorders from client-go
			Name:      fmt.Sprintf("%v.%x", instance.Name, now.UnixNano()),
			Namespace: instance.Namespace,
		},
		Reason:  fmt.Sprintf("policy: %s/%s", instance.Namespace, instance.Name),
		Message: convertPolicyStatusToString(instance, DefaultDuration),
		Source: corev1.EventSource{
			Component: ControllerName,
			Host:      r.InstanceName,
		},
		FirstTimestamp: metav1.NewTime(now),
		LastTimestamp:  metav1.NewTime(now),
		Count:          1,
		Type:           "Normal",
		Action:         "ComplianceStateUpdate",
		Related: &corev1.ObjectReference{
			Kind:       instance.Kind,
			Namespace:  instance.Namespace,
			Name:       instance.Name,
			UID:        instance.UID,
			APIVersion: instance.APIVersion,
		},
		ReportingController: ControllerName,

		ReportingInstance: r.InstanceName,
	}

	if instance.Status.ComplianceState == policyv1.NonCompliant {
		event.Type = "Warning"
	}

	if len(instance.OwnerReferences) > 0 {
		ownerRef := instance.OwnerReferences[0]
		event.InvolvedObject = corev1.ObjectReference{
			Kind:       ownerRef.Kind,
			Namespace:  instance.Namespace, // k8s ensures owners are always in the same namespace
			Name:       ownerRef.Name,
			UID:        ownerRef.UID,
			APIVersion: ownerRef.APIVersion,
		}
	} else {
		event.InvolvedObject = corev1.ObjectReference{
			Kind:       instance.Kind,
			Namespace:  instance.Namespace, // k8s ensures owners are always in the same namespace
			Name:       instance.Name,
			UID:        instance.UID,
			APIVersion: instance.APIVersion,
		}
	}

	return r.Create(ctx, event)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificatePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(&policyv1.CertificatePolicy{}).
		Complete(r)
}
