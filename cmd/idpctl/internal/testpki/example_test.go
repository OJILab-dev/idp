package testpki_test

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
)

// Example shows an HTTPS round trip: the client presents no certificate and
// still verifies the server through RootCAs.
func Example() {
	t := &testing.T{}
	server := testpki.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, len(r.TLS.PeerCertificates))
	}))
	defer server.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    testpki.RootCAs(server),
		MinVersion: tls.VersionTLS12,
	}}}
	resp, err := client.Get(server.URL)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	// Output: 200
}

// ExampleEncodePKCS8 encodes a throwaway admin key as the PEM idpctl reads.
func ExampleEncodePKCS8() {
	t := &testing.T{}
	keyPEM := testpki.EncodePKCS8(t, testpki.NewECDSAKey(t, elliptic.P384()))
	fmt.Println(string(keyPEM[:27]))
	// Output: -----BEGIN PRIVATE KEY-----
}
