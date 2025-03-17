package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/lcrownover/mtls-go/internal/ca"
	"github.com/lcrownover/mtls-go/internal/server"
)

type cliOptions struct {
	dataPath   string
	serverName string
}

func parseEnv() *cliOptions {
	opts := &cliOptions{
		dataPath:   "/var/lib/caravel",
		serverName: "localhost",
	}

	if v, found := os.LookupEnv("CARAVEL_DATA_PATH"); found {
		opts.dataPath = v
	}
	if v, found := os.LookupEnv("CARAVEL_SERVER_NAME"); found {
		opts.serverName = v
	}
	return opts
}

func main() {

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	opts := parseEnv()
	caPath := filepath.Join(opts.dataPath, "ca")

	err := server.Initialize(opts.dataPath)
	if err != nil {
		logger.Error("failed to initialize server", "error", err)
	}

	// initialize the CA dir structure, creates key/cert
	caCert, err := ca.InitializeCA(opts.dataPath, []string{opts.serverName})
	if err != nil {
		logger.Error("failed to initialize CA", "error", err)
	}

	// inits the server certificates
	err = ca.InitializeServerCertificate(caPath, caCert, []string{opts.serverName})
	if err != nil {
		logger.Error("failed to initialize server certificates", "error", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		psk := r.Header.Get("X-Register-Key")
		if psk != "letmein" {
			logger.Info("client tried to register with invalid key", "ip", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		name := r.Header.Get("X-Agent-Name")
		if name == "" {
			logger.Info("client tried to register with empty name", "ip", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		logger.Info("registering new agent", "name", name)
		fmt.Fprintf(w, "registering new agent: %s\n", name)
		keypair, err := ca.RegisterAgent(caPath, caCert, name)
		if err != nil {
			logger.Error("failed to register new agent", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		certPEM, keyPEM, err := ca.TLSCertToPEM(*keypair)
		if err != nil {
			logger.Error("failed to encode keypair to PEM", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, certPEM)
		fmt.Fprintln(w, keyPEM)
	})

	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			logger.Info("client tried to connect with invalid cert", "ip", r.RemoteAddr)
			http.Error(w, "invalid certificate", http.StatusUnauthorized)
			return
		}
		fmt.Fprintln(w, "you made it!")
	})

	pemBytes, err := ca.GetPEMBytes(caCert)
	if err != nil {
		logger.Error("failed to encode CA certificate to PEM")
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(pemBytes); !ok {
		logger.Error("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.VerifyClientCertIfGiven,
	}

	server := &http.Server{
		Addr:      ":9140",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting server")
	if err := server.ListenAndServeTLS(ca.ServerCertificatePath(caPath), ca.ServerKeyPath(caPath)); err != nil {
		logger.Error("failed to start server", "error", err)
	}
}
