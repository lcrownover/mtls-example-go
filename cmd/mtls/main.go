package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
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
	opts := parseEnv()

	err := server.Initialize(opts.dataPath)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	caCert, err := ca.InitializeCA(opts.dataPath, []string{opts.serverName})
	if err != nil {
		log.Fatalf("failed to initialize CA: %v", err)
	}

	caPath := filepath.Join(opts.dataPath, "ca")
	err = ca.InitializeServerCertificate(caPath, caCert, []string{opts.serverName})
	if err != nil {
		log.Fatalf("failed to initialize server certificates: %v", err)
	}
	serverCertPath := ca.CACertificatePath(caPath)
	serverKeyPath := ca.CAKeyPath(caPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert.Certificate[0])

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":9140",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting server")
	log.Fatal(server.ListenAndServeTLS(serverCertPath, serverKeyPath))
}
