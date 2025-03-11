package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lcrownover/mtls-go/internal/ca"
	"github.com/lcrownover/mtls-go/internal/server"
)

var basePath = "/var/lib/caravel-go"

func main() {
	err := server.InitializeServer(basePath)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	ca, err := ca.NewCertificateAuthority(basePath, []string{"localhost"})
	if err != nil {
		log.Fatalf("failed to initialize CA: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	caCert, _ := os.ReadFile("/var/lib/caravel/ca/ca.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*ca.ServerKeyPair},
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":9140",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Starting server")
	log.Fatal(server.ListenAndServeTLS("/var/lib/caravel/ca/server/localhost.crt", "/var/lib/caravel/ca/server/localhost.key"))
}
