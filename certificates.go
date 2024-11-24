package CADDY_PFX_CERTIFICATES

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func getCertificateChain(initialCerts []*x509.Certificate) ([]*x509.Certificate, error) {
	certsState := &certState{}
	var fullChain []*x509.Certificate

	// Add initial certificates to the state
	for _, cert := range initialCerts {
		addOrUpdateState(certsState, cert)
		fullChain = append(fullChain, cert)
	}

	// Resolve the full chain, including downloading missing certificates
	resolvedCerts, err := getUnresolvedCertificates(certsState)
	if err != nil {
		return nil, err
	}

	// Append resolved certificates to the PEM data
	for _, cert := range resolvedCerts {
		fullChain = append(fullChain, cert)
	}

	return fullChain, nil
}

type CertificateState struct {
	SubjectKeyId           string
	AuthorityKeyId         string
	Resolved               bool
	IssuingCertificateURLs []string
}

type certState []CertificateState

func addOrUpdateState(certsState *certState, cert *x509.Certificate) {
	for i := range *certsState {
		if (*certsState)[i].SubjectKeyId == string(cert.SubjectKeyId) {
			return
		}
	}

	*certsState = append(*certsState, CertificateState{
		SubjectKeyId:           string(cert.SubjectKeyId),
		AuthorityKeyId:         string(cert.AuthorityKeyId),
		IssuingCertificateURLs: cert.IssuingCertificateURL,
	})

	var unresolvedCerts []CertificateState
	for _, state := range *certsState {
		if state.AuthorityKeyId != string(cert.SubjectKeyId) {
			unresolvedCerts = append(unresolvedCerts, state)
		}
	}
	*certsState = unresolvedCerts
}

func getUnresolvedCertificates(certsState *certState) ([]*x509.Certificate, error) {
	var resolvedCerts []*x509.Certificate
	if len(*certsState) == 0 {
		return resolvedCerts, nil
	}

	state := (*certsState)[0]
	*certsState = (*certsState)[1:] // Shift

	for _, url := range state.IssuingCertificateURLs {
		cert, err := fetchCertificateFromURL(url)
		if err != nil {
			continue // Skip on error but continue processing
		}
		resolvedCerts = append(resolvedCerts, cert)
		addOrUpdateState(certsState, cert) // Recursively append remaining certificates
	}

	// Recur for the remaining unresolved certificates
	moreResolved, err := getUnresolvedCertificates(certsState)
	if err != nil {
		return nil, err
	}

	// Combine resolved certificates
	resolvedCerts = append(resolvedCerts, moreResolved...)
	return resolvedCerts, nil
}

func fetchCertificateFromURL(url string) (cert *x509.Certificate, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from URL %s: %v", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate data: %v", err)
	}

	// Try to decode in PEM
	block, _ := pem.Decode(certData)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate: %v", err)
		}
		return cert, nil
	}

	// Try to decode in DER
	cert, err = x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %v", err)
	}

	return cert, nil
}
