package testpki_test

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"

	"github.com/OJILab-dev/idp/cmd/idpctl/internal/testpki"
)

// Example shows an mTLS round trip: a throwaway CA issues a client
// certificate, and a client that presents it reaches the test server while
// still verifying the server.
func Example() {
	t := &testing.T{}
	ca := testpki.NewCA(t)
	server := ca.NewMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, len(r.TLS.PeerCertificates))
	}))
	defer server.Close()

	certPEM, keyPEM := ca.IssueClient(t, testpki.NewECDSAKey(t, elliptic.P384()))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fmt.Println(err)
		return
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      testpki.RootCAs(server),
		MinVersion:   tls.VersionTLS12,
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
