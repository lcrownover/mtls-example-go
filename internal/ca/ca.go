package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type caConfig struct {
	basePath       string
	caKeyPath      string
	caCertPath     string
	serverPath     string
	serverKeyPath  string
	serverCertPath string
	agentsPath     string
}

func NewCAConfig(dataPath string) *caConfig {
	basePath := filepath.Join(dataPath, "ca")
	caKeyPath := filepath.Join(basePath, "ca.key")
	caCertPath := filepath.Join(basePath, "ca.crt")
	serverPath := filepath.Join(basePath, "server")
	serverKeyPath := filepath.Join(serverPath, "server.key")
	serverCertPath := filepath.Join(serverPath, "server.crt")
	return &caConfig{
		basePath:       basePath,
		caKeyPath:      caKeyPath,
		caCertPath:     caCertPath,
		serverPath:     serverPath,
		serverKeyPath:  serverKeyPath,
		serverCertPath: serverCertPath,
	}
}

func InitializeCA(dataPath string, hostnames []string) (*tls.Certificate, error) {
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("hostnames for CA must not be empty")
	}
	cfg := NewCAConfig(dataPath)

	var err error
	var caKey *rsa.PrivateKey
	var caCert *x509.Certificate

	err = createCADirs(cfg.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA directories: %v", err)
	}

	// load the CA private key
	if _, err := os.Stat(cfg.caKeyPath); os.IsNotExist(err) {
		caKey, err = generatePKCS8PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ca private key: %v", err)
		}
		err = savePKCS8PrivateKey(cfg.caKeyPath, caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to save ca private key: %v", err)
		}
	}
	caKey, err = loadPKCS8PrivateKey(cfg.caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ca private key from disk: %v", err)
	}

	// load the CA certificate
	if _, err := os.Stat(cfg.caCertPath); os.IsNotExist(err) {
		caCertTemplate, err := generateCertificateTemplate(true, []string{})
		if err != nil {
			return nil, fmt.Errorf("failed to generate ca certificate template: %v", err)
		}
		caCert, err = signCertificateTemplate(caCertTemplate, caCertTemplate, caKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign ca certificate: %v", err)
		}
		err = saveCertificate(cfg.caCertPath, caCert)
		if err != nil {
			return nil, fmt.Errorf("failed to save ca certificate: %v", err)
		}
	}

	keypair, err := tls.LoadX509KeyPair(cfg.caCertPath, cfg.caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 keypair: %v", err)
	}

	return &keypair, nil
}

func createCADirs(caPath string) error {
	// create the ca path
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		err := os.Mkdir(caPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create CA directory: %v", err)
		}
	}
	// create the ca/server path
	serverPath := filepath.Join(caPath, "server")
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		err := os.Mkdir(serverPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create server directory: %v", err)
		}
	}
	// create the ca/agents path
	agentsPath := filepath.Join(caPath, "agents")
	if _, err := os.Stat(agentsPath); os.IsNotExist(err) {
		err := os.Mkdir(agentsPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create agents directory: %v", err)
		}
	}
	return nil
}

func loadPKCS8PrivateKey(path string) (*rsa.PrivateKey, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pkcs8 key from file: %v", err)
	}
	keyPEM, _ := pem.Decode(k)
	parseResult, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pkcs8 key: %v", err)
	}
	key := parseResult.(*rsa.PrivateKey)
	return key, nil

}

func loadPEMCertificate(path string) (*x509.Certificate, error) {
	c, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pem cert from file: %v", err)
	}
	certPEM, _ := pem.Decode(c)
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem cert: %v", err)
	}
	return cert, nil
}

func generatePKCS8PrivateKey() (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa private key: %v", err)
	}
	return privKey, nil
}

func savePKCS8PrivateKey(path string, key *rsa.PrivateKey) error {
	pkcs8keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal pkcs8 from key: %v", err)
	}
	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs8keyBytes,
	})
	err = os.WriteFile(path, keyPEM.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("failed to write pkcs8 key file: %v", err)
	}
	return nil
}

func generateCertificateTemplate(isCA bool, hostnames []string) (*x509.Certificate, error) {
	if isCA && len(hostnames) != 0 {
		return nil, fmt.Errorf("if creating a CA certificate, don't pass hostnames")
	}
	if !isCA && len(hostnames) == 0 {
		return nil, fmt.Errorf("if creating a client certificate, pass at least one hostname")
	}
	var orgName string
	if isCA {
		orgName = "Caravel CA"
	} else {
		orgName = "Caravel Client"
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{orgName},
			Country:      []string{"US"},
			Province:     []string{"Oregon"},
			Locality:     []string{"Eugene"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if isCA {
		cert.IsCA = isCA
		cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	}
	if len(hostnames) > 0 {
		cert.DNSNames = hostnames
	}
	return cert, nil
}

func signCertificateTemplate(template *x509.Certificate, parent *x509.Certificate, key *rsa.PrivateKey, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

func saveCertificate(path string, cert *x509.Certificate) error {
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err := os.WriteFile(path, certPEM.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("failed to write cert to file: %v", err)
	}
	return nil
}

func InitializeServerCertificate(caPath string, caCert *tls.Certificate, hostnames []string) error {
	serverPath := filepath.Join(caPath, "server")
	key, err := generatePKCS8PrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %v", err)
	}
	t, err := generateCertificateTemplate(false, hostnames)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %v", err)
	}

	cax509Cert, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate from ca certificate: %v", err)
	}
	caPrivateKey := caCert.PrivateKey.(*rsa.PrivateKey)

	cert, err := signCertificateTemplate(t, cax509Cert, key, caPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to sign server certificate: %v", err)
	}
	err = saveCertificate(filepath.Join(serverPath, "server.crt"), cert)
	if err != nil {
		return fmt.Errorf("failed to save server certificate: %v", err)
	}
	err = savePKCS8PrivateKey(filepath.Join(serverPath, "server.key"), key)
	if err != nil {
		return fmt.Errorf("failed to save server private key: %v", err)
	}
	return nil
}

func CAKeyPath(caPath string) string {
	return filepath.Join(caPath, "ca.key")
}
func CACertificatePath(caPath string) string {
	return filepath.Join(caPath, "ca.crt")
}

func ServerCertificatePath(caPath string) string {
	return filepath.Join(caPath, "server", "server.crt")
}
func ServerKeyPath(caPath string) string {
	return filepath.Join(caPath, "server", "server.key")
}

func AgentCertificatePath(caPath, agentName string) string {
	return filepath.Join(caPath, "agents", fmt.Sprintf("%s.crt", agentName))
}
func AgentKeyPath(caPath, agentName string) string {
	return filepath.Join(caPath, "agents", fmt.Sprintf("%s.key", agentName))
}

// func generateServerCertificate(ca *CertificateAuthority) (*tls.Certificate, error) {
// 	cert := &x509.Certificate{
// 		SerialNumber: big.NewInt(2019),
// 		Subject: pkix.Name{
// 			Organization: []string{"Caravel"},
// 			Country:      []string{"US"},
// 			Province:     []string{},
// 			Locality:     []string{"Eugene"},
// 		},
// 		DNSNames:     ca.Hostnames,
// 		NotBefore:    time.Now(),
// 		NotAfter:     time.Now().AddDate(30, 0, 0),
// 		SubjectKeyId: []byte{1, 2, 3, 4, 6},
// 		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
// 		KeyUsage:     x509.KeyUsageDigitalSignature,
// 	}
//
// 	certPrivKey, err := generatePKCS8PrivateKey(ca.ServerKeyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate server private key: %v", err)
// 	}
//
// 	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.CACertificate, &certPrivKey.PublicKey, ca.CAPrivateKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signed certificate: %v", err)
// 	}
//
// 	certPEM := new(bytes.Buffer)
// 	pem.Encode(certPEM, &pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: certBytes,
// 	})
//
// 	certPrivKeyPEM := new(bytes.Buffer)
// 	pem.Encode(certPrivKeyPEM, &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
// 	})
//
// 	err = os.WriteFile(ca.ServerCertPath, certPEM.Bytes(), 0600)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to write server cert file: %v", err)
// 	}
//
// 	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create keypair: %v", err)
// 	}
//
// 	return &serverCert, nil
// }
