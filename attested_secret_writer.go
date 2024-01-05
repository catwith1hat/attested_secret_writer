package attested_secret_writer

import (
	"context"
	"github.com/edgelesssys/ego/enclave"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func GetOneSecret() ([]byte, error) {
	// Create a TLS config with a self-signed certificate and an embedded report.
	tlsCfg, err := enclave.CreateAttestationServerTLSConfig()
	if err != nil {
		panic(err)
	}

	secretChannel := make(chan []byte)
	// Create HTTPS server.
	srv := http.Server{Addr: "0.0.0.0:8080", TLSConfig: tlsCfg}
	go func() {
		defer close(secretChannel)

		// Handle requests and send a signal to shutdown after the first request
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
				return
			}
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			secretChannel <- data
			w.WriteHeader(http.StatusOK)
		})

		if err := srv.ListenAndServeTLS("", ""); err != nil {
			if err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}
	}()
	secret := <-secretChannel
	// Gracefully shut down the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Shutdown(ctx)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func WriteSecret() {
	secret, err := GetOneSecret()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("/secret", secret, 0600); err != nil {
		log.Fatal(err)
	}
}
