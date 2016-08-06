package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)
// TLSHealthChecker implements health.Checkable
type TLSHealthChecker struct {
	cert *x509.Certificate
	dur  time.Duration
}

// Healthy returns error if it could not loaded certificate or validity bounds invalid
func (hc *TLSHealthChecker)Healthy() error {
	if hc.cert == nil {
		return errors.New("Certificate is not found.")
	}
	if hc.cert.NotBefore.Before(time.Now()) {
		return errors.New("Certificate valid date is not started.")
	}
	if hc.cert.NotAfter.After(time.Now().Add(hc.dur)) {
		return errors.New("Certificate will be invalid after given duration.")
	}
	return nil
}

// New returns TLSHealthChecker
func New(certFile, keyFile string, d time.Duration) *TLSHealthChecker {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return &TLSHealthChecker{cert:nil}
	}
	return &TLSHealthChecker{cert:c.Leaf, dur:d}
}

// NewWithCert returns TLSHealthChecker
func NewWithCert(cert *x509.Certificate, d time.Duration) *TLSHealthChecker {
	return &TLSHealthChecker{cert:cert, dur:d}
}