// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
package util

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/golang/glog"
)

// DecodeCertificatePolicyBytes Decodes certificate bytes, accepts certificate chains too
// Returns the list of x509 CertificatePolicy objects that were encoded in the certificate bytes
func DecodeCertificatePolicyBytes(certBytes []byte) []*x509.CertificatePolicy {
	certs := []*x509.CertificatePolicy{}
	// Decode into x509 cert
	for {
		var block *pem.Block
		// decode the tls certificate pem
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificatePolicy(block.Bytes)
		if err != nil {
			glog.Infof("Error decoding certificate bytes, error: %s", err.Error())
		}
		certs = append(certs, cert)
	}
	return certs
}
