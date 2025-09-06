package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// EnsureCA creates a CA certificate and key if they don't exist
func EnsureCA(keyPath, certPath string) error {
	// Check if CA already exists
	if _, err := os.Stat(keyPath); err == nil {
		if _, err := os.Stat(certPath); err == nil {
			return nil // CA already exists
		}
	}

	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "SSTP Private CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	// Create CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save CA private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	}); err != nil {
		return err
	}

	// Save CA certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}); err != nil {
		return err
	}

	return nil
}

// EnsureServerCertForIP creates a server certificate for the given IP if needed
func EnsureServerCertForIP(certPath, keyPath, caCertPath, caKeyPath string, ip net.IP) error {
	// Load CA
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	// Check if server cert already exists and is valid for this IP
	if valid, err := isCertValidForIP(certPath, ip); err == nil && valid {
		return nil // Certificate is valid
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: ip.String(),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 825), // ~825 days (maximum for publicly trusted certs)
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{ip},
	}

	// Create server certificate
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save server private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	}); err != nil {
		return err
	}

	// Save server certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	}); err != nil {
		return err
	}

	return nil
}

// loadCA loads the CA certificate and private key
func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load CA certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load CA private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, err
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

// isCertValidForIP checks if the certificate exists and is valid for the given IP
func isCertValidForIP(certPath string, ip net.IP) (bool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return false, nil
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, err
	}

	// Check if certificate is still valid
	if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		return false, nil
	}

	// Check if IP is in certificate
	for _, certIP := range cert.IPAddresses {
		if certIP.Equal(ip) {
			return true, nil
		}
	}

	return false, nil
}

// WriteCACert writes the CA certificate to the provided writer
func WriteCACert(certPath string, writer interface {
	Write([]byte) (int, error)
}) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	_, err = writer.Write(certPEM)
	return err
}
