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

type CertificateAuthority struct {
	Hostnames         []string
	CAPath            string
	CAKeyPath         string
	CACertPath        string
	CACertificate     *x509.Certificate
	CAPrivateKey      *rsa.PrivateKey
	CAKeyPair         *tls.Certificate
	ServerKeyPath     string
	ServerCertPath    string
	ServerCertificate *x509.Certificate
	ServerPrivateKey  *rsa.PrivateKey
	ServerKeyPair     *tls.Certificate
}

func NewCertificateAuthority(dataPath string, hostnames []string) (*CertificateAuthority, error) {
	var err error
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("hostnames for CA must not be empty")
	}
	caPath := filepath.Join(dataPath, "ca")

	ca := &CertificateAuthority{
		Hostnames:      hostnames,
		CAPath:         caPath,
		CAKeyPath:      filepath.Join(caPath, "ca.key"),
		CACertPath:     filepath.Join(caPath, "ca.crt"),
		ServerKeyPath:  filepath.Join(caPath, "server", fmt.Sprintf("%s.key", hostnames[0])),
		ServerCertPath: filepath.Join(caPath, "server", fmt.Sprintf("%s.crt", hostnames[0])),
	}

	err = initializeCA(ca)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ca: %v", err)
	}
	return ca, nil
}

func initializeCA(ca *CertificateAuthority) error {
	if _, err := os.Stat(ca.CAPath); os.IsNotExist(err) {
		err := os.Mkdir(ca.CAPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create CA directory: %v", err)
		}
	}
	serverPath := filepath.Join(ca.CAPath, "server")
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		err := os.Mkdir(serverPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create server directory: %v", err)
		}
	}
	agentsPath := filepath.Join(ca.CAPath, "agents")
	if _, err := os.Stat(agentsPath); os.IsNotExist(err) {
		err := os.Mkdir(agentsPath, 0700)
		if err != nil {
			return fmt.Errorf("failed to create agents directory: %v", err)
		}
	}
	if _, err := os.Stat(ca.CAKeyPath); os.IsNotExist(err) {
		// generate will also store a copy on disk
		caKey, err := generatePrivateKey(ca.CAKeyPath)
		if err != nil {
			return fmt.Errorf("failed to generate ca private key: %v", err)
		}
		ca.CAPrivateKey = caKey
	} else {
		// it exists, load from disk
		caKey, err := loadCAPrivateKey(ca.CAKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load private key: %v", err)
		}
		ca.CAPrivateKey = caKey
	}
	if _, err := os.Stat(ca.CACertPath); os.IsNotExist(err) {
		// generate will also store a copy on disk
		caCert, err := generateCACertificate(ca.CACertPath, ca.CAPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to generate ca cert: %v", err)
		}
		ca.CACertificate = caCert
	} else {
		caCert, err := loadCACertificate(ca.CACertPath)
		if err != nil {
			return fmt.Errorf("failed to load pem cert: %v", err)
		}
		ca.CACertificate = caCert
	}
	keypair, err := tls.LoadX509KeyPair(ca.CACertPath, ca.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load x509 keypair: %v", err)
	}
	ca.CAKeyPair = &keypair

	serverKeyPair, err := generateServerCertificate(ca)
	if err != nil {
		return fmt.Errorf("failed to generate server cert: %v", err)
	}
	ca.ServerKeyPair = serverKeyPair
	return nil
}

func loadCAPrivateKey(caKeyPath string) (*rsa.PrivateKey, error) {
	kb, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca key from file: %v", err)
	}
	keyPEM, _ := pem.Decode(kb)
	parseResult, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca pkcs8 key: %v", err)
	}
	key := parseResult.(*rsa.PrivateKey)
	return key, nil

}

func loadCACertificate(caCertPath string) (*x509.Certificate, error) {
	cb, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca cert from file: %v", err)
	}
	certPEM, _ := pem.Decode(cb)
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca cert: %v", err)
	}
	return cert, nil
}

// func loadServerPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
// 	kb, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read server key from file: %v", err)
// 	}
// 	keyPEM, _ := pem.Decode(kb)
// 	parseResult, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse server pkcs8 key: %v", err)
// 	}
// 	key := parseResult.(*rsa.PrivateKey)
// 	return key, nil
//
// }

// func loadServerCertificate(certPath string) (*x509.Certificate, error) {
// 	cb, err := os.ReadFile(certPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read server cert from file: %v", err)
// 	}
// 	certPEM, _ := pem.Decode(cb)
// 	cert, err := x509.ParseCertificate(certPEM.Bytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse server cert: %v", err)
// 	}
// 	return cert, nil
// }

func generatePrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa private key: %v", err)
	}
	pkcs8keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pkcs8 from private key: %v", err)
	}
	caKeyPEM := new(bytes.Buffer)
	pem.Encode(caKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs8keyBytes,
	})
	err = os.WriteFile(keyPath, caKeyPEM.Bytes(), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write pkcs8 key file: %v", err)
	}
	return privKey, nil
}

func generateCACertificate(certPath string, key *rsa.PrivateKey) (*x509.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{"Caravel"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"Eugene"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	err = os.WriteFile(certPath, certPEM.Bytes(), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write ca cert file: %v", err)
	}
	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca cert: %v", err)
	}
	return cert, nil
}

func generateServerCertificate(ca *CertificateAuthority) (*tls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Caravel"},
			Country:      []string{"US"},
			Province:     []string{},
			Locality:     []string{"Eugene"},
		},
		DNSNames:     ca.Hostnames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := generatePrivateKey(ca.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %v", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.CACertificate, &certPrivKey.PublicKey, ca.CAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed certificate: %v", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	err = os.WriteFile(ca.ServerCertPath, certPEM.Bytes(), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write server cert file: %v", err)
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create keypair: %v", err)
	}

	return &serverCert, nil
}
