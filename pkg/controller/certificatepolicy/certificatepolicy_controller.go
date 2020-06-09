// Copyright (c) 2020 Red Hat, Inc.
package certificatepolicy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"
	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
	"github.com/open-cluster-management/cert-policy-controller/pkg/common"
	"github.com/open-cluster-management/cert-policy-controller/pkg/controller/util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
	err = c.Watch(&source.Kind{Type: &policyv1.CertificatePolicy{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to CertificatePolicy resources
	err = c.Watch(&source.Kind{Type: &policyv1.CertificatePolicy{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &policyv1.CertificatePolicy{},
	})
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
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			handleRemovingPolicy(request.NamespacedName.Name)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		updateNeeded := false
		if !ensureDefaultLabel(instance) {
			glog.Info("Label update needed")
			updateNeeded = true
		}
		if updateNeeded {
			if err := r.client.Update(context.Background(), instance); err != nil {
				glog.Info("Requeing due to error updating the label")
				return reconcile.Result{Requeue: true}, nil
			}
		}
		instance.Status.CompliancyDetails = nil //reset CompliancyDetails
		err := handleAddingPolicy(instance)
		if err != nil {
			glog.V(3).Infof("Failed to handleAddingPolicy")
		}
	}

	glog.Infof("reason: successful processing, subject: policy/%v, namespace: %v, according to policy: %v, additional-info: none\n", instance.Name, instance.Namespace, instance.Name)
	return reconcile.Result{}, nil
}

func ensureDefaultLabel(instance *policyv1.CertificatePolicy) (updateNeeded bool) {
	glog.Info("ensureDefaultLabel")
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
func PeriodicallyExecCertificatePolicies(freq uint) {
	glog.Info("PeriodicallyExecCertificatePolicies")
	var plcToUpdateMap map[string]*policyv1.CertificatePolicy
	for {
		start := time.Now()
		printMap(availablePolicies.PolicyMap)

		plcToUpdateMap = make(map[string]*policyv1.CertificatePolicy)

		// Loops through all of the cert policies
		for resource, policy := range availablePolicies.PolicyMap {
			namespace := strings.Split(resource, "/")[0]
			glog.Infof("Checking certificates in namespace %s defined in policy %s", namespace, policy.Name)
			update, nonCompliant, list := certExpiration(policy, namespace)
			if strings.ToLower(string(policy.Spec.RemediationAction)) == strings.ToLower(string(policyv1.Enforce)) {
				glog.Infof("Enforce is set, but ignored :-)")
			}
			message := fmt.Sprintf("Found %d non compliant certificates in the namespace %s.\n", nonCompliant, namespace)
			if nonCompliant > 0 {
				message = fmt.Sprintf("%sList of non compliant certificates:\n", message)
				for cert, certDetails := range list {
					message = fmt.Sprintf("%s%s expires in %s\n", message, cert, certDetails.Expiration)
				}
			}
			glog.Info(message)

			if addViolationCount(policy, message, nonCompliant, namespace, list) || update {
				plcToUpdateMap[policy.Name] = policy
			}
			checkComplianceBasedOnDetails(policy)
			glog.Infof("Finished processing policy %s, on namespace %s", policy.Name, namespace)
		}

		//update status of all policies that changed:
		faultyPlc, err := updatePolicyStatus(plcToUpdateMap)
		if err != nil {
			glog.Errorf("reason: policy update error, subject: policy/%v, namespace: %v, according to policy: %v, additional-info: %v\n", faultyPlc.Name, faultyPlc.Namespace, faultyPlc.Name, err)
		}

		//prometheus quantiles for processing delay in each cycle
		elapsed := time.Since(start)
		//making sure that if processing is > freq we don't sleep
		//if freq > processing we sleep for the remaining duration
		elapsed = time.Since(start) / 1000000000 // convert to seconds
		if float64(freq) > float64(elapsed) {
			remainingSleep := float64(freq) - float64(elapsed)
			time.Sleep(time.Duration(remainingSleep) * time.Second)
		}
	}
}

// Checks each namespace for certificates that are going to expire within 3 months
// Returns the number of uncompliant certificates and a list of the uncompliant certificates
func certExpiration(policy *policyv1.CertificatePolicy, namespace string) (bool, uint, map[string]policyv1.Cert) {
	glog.Info("certExpiration")
	update := false
	nonCompliantCertificates := make(map[string]policyv1.Cert, 0)
	//TODO: Want the label selector to find secrets with certificates only!! -> is-certificate
	// Loops through all the secrets within the CertificatePolicy's specified namespace
	secretList, _ := (*common.KubeClient).CoreV1().Secrets(namespace).List(metav1.ListOptions{LabelSelector: labels.Set(policy.Spec.LabelSelector).String()})
	for _, secretItem := range secretList.Items {
		secret := secretItem
		glog.V(3).Infof("Checking secret %s", secret.Name)
		notCompliant, reason, expiration := checkExpiration(&secret, policy.Spec.MinDuration)
		if notCompliant {
			certName := secret.Name
			// Gets the certificate's name if it exists
			if secret.Labels[certNameLabel] != "" {
				certName = secret.Labels[certNameLabel]
			} else if secret.Labels[certManagerNameLabel] != "" {
				certName = secret.Labels[certManagerNameLabel]
			}
			glog.V(3).Infof("reason: %v, secret: %v, according to policy: %v\n", reason, secret.ObjectMeta.Name, policy.Name)
			msg := fmt.Sprintf("Certificate %s [secret name: %s] expires in %s", certName, secret.ObjectMeta.Name, expiration)
			glog.V(3).Info(msg)
			nonCompliantCertificates[certName] = policyv1.Cert{Secret: secret.Name, Expiration: expiration}
			if policy.Status.ComplianceState != policyv1.NonCompliant {
				update = true
			}
		}
	}
	return update, uint(len(nonCompliantCertificates)), nonCompliantCertificates
}

// Returns true only if the secret (certificate) is not compliant (expires within the given duration)
func checkExpiration(secret *corev1.Secret, policyDuration *metav1.Duration) (bool, string, string) {
	glog.Info("checkExpiration")
	keyName := "certificate_key_name"
	key := "tls.crt"
	if secret.Labels != nil && secret.Labels[keyName] != "" {
		key = secret.Labels[keyName]
	}
	glog.V(3).Infof("Checking secret %s with certificate key %s", secret.Name, key)
	// Get the certificate bytes
	certBytes, _ := secret.Data[key]

	// Get the x509 Certificates
	certs := util.DecodeCertificateBytes(certBytes)
	if len(certs) < 1 {
		glog.Infof("The secret %s does not contain any certificates. Skipping this secret.", secret.Name)
		return false, "No certificates", ""
	}
	x509Cert := certs[0] // Certificate chains always begin with the end user certificate as a standard format

	// Get time now and subtract from cert's not before
	now := time.Now()
	expiration := x509Cert.NotAfter
	duration := expiration.Sub(now)
	minimumDuration := DefaultDuration

	if policyDuration != nil {
		minimumDuration = policyDuration.Duration
	}
	if duration < minimumDuration {
		msg := fmt.Sprintf("Secret %s not compliant! Expires in %s, less than %s from now %s", secret.ObjectMeta.Name, duration.String(), minimumDuration.String(), now.String())
		return true, msg, duration.String()
	}
	return false, "", ""
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
	glog.Info("addViolationCount")
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

	// The number of non-compliant certificates has changed, so change the overall compliance state
	if plc.Status.CompliancyDetails[namespace].NonCompliantCertificates != count {
		changed = true
	}

	plc.Status.CompliancyDetails[namespace] = policyv1.CompliancyDetails{
		NonCompliantCertificates:     count,
		NonCompliantCertificatesList: certificates,
		Message:                      msg,
	}
	glog.Infof("The policy %s has been updated with the message: %s", plc.Name, msg)
	return changed
}

// checkComplianceBasedOnDetails takes a certificate and sets whether
// the policy is compliant or not based on the certificate's status
func checkComplianceBasedOnDetails(plc *policyv1.CertificatePolicy) {
	glog.Info("checkComplianceBasedOnDetails")
	plc.Status.ComplianceState = policyv1.Compliant
	if plc.Status.CompliancyDetails == nil {
		return
	}
	if len(plc.Status.CompliancyDetails) == 0 {
		return
	}
	for namespace, details := range plc.Status.CompliancyDetails {
		if details.NonCompliantCertificates > 0 {
			glog.Infof("The number of violations in policy %s in namespace %s does not equal zero, therefore it is non compliant", plc.Name, namespace)
			plc.Status.ComplianceState = policyv1.NonCompliant
		}
	}
}

func checkComplianceChangeBasedOnDetails(plc *policyv1.CertificatePolicy) (complianceChanged bool) {
	glog.Info("checkComplianceChangeBasedOnDetails")
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
	glog.Info("Updating the Policy Status")
	for _, instance := range policies { // policies is a map where: key = plc.Name, value = pointer to plc
		err := reconcilingAgent.client.Status().Update(context.TODO(), instance)
		if err != nil {
			glog.Info("updatePolicyStatus, reconcile update failed")
			return instance, err
		}
		if EventOnParent != "no" {
			createParentPolicyEvent(instance)
		}
		message := fmt.Sprintf("%v", instance.Status.ComplianceState)
		glog.Infof("Policy %s Compliance State %s", instance.Name, message)
		for namespace, details := range instance.Status.CompliancyDetails {
			if details.NonCompliantCertificates > 0 {
				minDuration := DefaultDuration
				if instance.Spec.MinDuration != nil {
					minDuration = instance.Spec.MinDuration.Duration
				}
				message = fmt.Sprintf("%s; Non-compliant certificates (expires in less than %s) in %s[%d]:", message, minDuration.String(), namespace, details.NonCompliantCertificates)
				for cert, certDetails := range details.NonCompliantCertificatesList {
					message = fmt.Sprintf("%s [%s, %s]", message, cert, certDetails.Secret)
				}
				glog.Infof("Noncompliant certs %d %s", details.NonCompliantCertificates, message)
			}
		}
		if instance.Status.ComplianceState == policyv1.NonCompliant {
			reconcilingAgent.recorder.Event(instance, corev1.EventTypeWarning, "Policy updated", message)
		} else {
			reconcilingAgent.recorder.Event(instance, corev1.EventTypeNormal, "Policy updated", message)
		}
	}
	return nil, nil
}

func handleRemovingPolicy(name string) {
	glog.Info("handleRemovingPolicy")
	for k, v := range availablePolicies.PolicyMap {
		if v.Name == name {
			availablePolicies.RemoveObject(k)
		}
	}
}

func handleAddingPolicy(plc *policyv1.CertificatePolicy) error {
	glog.Info("handleAddingPolicy")
	allNamespaces, err := common.GetAllNamespaces()
	if err != nil {

		glog.Errorf("reason: error fetching the list of available namespaces, subject: K8s API server, namespace: all, according to policy: %v, additional-info: %v\n", plc.Name, err)

		return err
	}
	//clean up that policy from the existing namepsaces, in case the modification is in the namespace selector
	for _, ns := range allNamespaces {
		key := fmt.Sprintf("%s/%s", ns, plc.Name)
		if policy, found := availablePolicies.GetObject(key); found {
			if policy.Name == plc.Name {
				availablePolicies.RemoveObject(ns)
			}
		}
	}
	selectedNamespaces := common.GetSelectedNamespaces(plc.Spec.NamespaceSelector.Include, plc.Spec.NamespaceSelector.Exclude, allNamespaces)
	for _, ns := range selectedNamespaces {
		key := fmt.Sprintf("%s/%s", ns, plc.Name)
		availablePolicies.AddObject(key, plc)
	}
	return err
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
	glog.Info("createParentPolicyEvent")
	if len(instance.OwnerReferences) == 0 {
		return //there is nothing to do, since no owner is set
	}
	// we are making an assumption that the Certificate policy has a single owner, or we chose the first owner in the list
	if string(instance.OwnerReferences[0].UID) == "" {
		return //there is nothing to do, since no owner UID is set
	}

	parentPlc := createParentPolicy(instance)
	if instance.Status.ComplianceState == policyv1.NonCompliant {
		glog.Info("Update parent policy, non-compliant policy")
		reconcilingAgent.recorder.Event(&parentPlc, corev1.EventTypeWarning, fmt.Sprintf("policy: %s/%s", instance.Namespace, instance.Name), convertPolicyStatusToString(instance, DefaultDuration))
	} else {
		glog.Info("Update parent policy, compliant policy")
		reconcilingAgent.recorder.Event(&parentPlc, corev1.EventTypeNormal, fmt.Sprintf("policy: %s/%s", instance.Namespace, instance.Name), convertPolicyStatusToString(instance, DefaultDuration))
	}
}

func createParentPolicy(instance *policyv1.CertificatePolicy) policyv1.Policy {
	glog.Info("createParentPolicy")
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
