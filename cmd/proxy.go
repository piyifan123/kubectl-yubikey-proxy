package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
)

const (
	defaultPort = 8080
	exampleTxt  = `
Start a proxy points to cluster
 $ kubectl-yubikey-proxy --cluster-address=https://10.200.0.1 --cluster-ca=<base64 encoded cluster CA>
`
)

func NewCmd() *cobra.Command {
	srvAddr := ""
	srvCA := ""
	proxyPort := defaultPort

	cmd := &cobra.Command{
		Use:          "yubikey-proxy",
		Short:        "Start a local proxy to authenticate to the Kubernetes API server with Yubikey via mTLS",
		Example:      exampleTxt,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return startProxy(srvAddr, srvCA, proxyPort)
		},
	}

	cmd.Flags().StringVar(&srvAddr, "server-address", srvAddr, "Kubernetes API server address to connect")
	cmd.Flags().StringVar(&srvCA, "server-ca", srvCA, "Kubernetes API server CA cert (base64 encoded)")
	cmd.Flags().IntVar(&proxyPort, "proxy-port", defaultPort, fmt.Sprintf("local proxy port number. Defaults to %d", defaultPort))
	return cmd
}

func startProxy(srvAddrStr string, srvCAStr string, proxyPort int) error {
	if srvAddrStr == "" {
		return fmt.Errorf("You must provide a the k8s API server address via the --server-address flag")
	}
	if !strings.HasPrefix(srvAddrStr, "https://") {
		return fmt.Errorf("You must provide a the k8s API server address starts with 'https://'")
	}
	srvAddr, err := url.Parse(srvAddrStr)
	if err != nil {
		return fmt.Errorf("Failed to parse server URL: %w", err)
	}

	if srvCAStr == "" {
		return fmt.Errorf("You must provide a base64 encoded CA certificate of the k8s API server via the --server-ca flag")
	}
	srvCA, err := base64.StdEncoding.DecodeString(srvCAStr)
	if err != nil {
		return fmt.Errorf("Failed to decode base64 CA cert of the k8s API server: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(srvCA)

	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("Unable to read PIV cards: %w", err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if yk, err = piv.Open(card); err != nil {
				return fmt.Errorf("Unable to open yubikey: %w", err)
			}
			break
		}
	}
	if yk == nil {
		return fmt.Errorf("No Yubikey attached")
	}

	cert, err := yk.Certificate(piv.SlotAuthentication)
	if err != nil {
		return fmt.Errorf("Unable to read cert from the Yubikey authentication (9a) slot: %w", err)
	}
	// Create a crypto.PrivateKey that implements crypto.Decrypter to make Yubikey act as a crypto
	// oracle to perform TLS handshake with the stored x509 client cert private key (without revealing
	// the private key).
	pk, err := yk.PrivateKey(piv.SlotAuthentication, cert.PublicKey, piv.KeyAuth{})
	if err != nil {
		return fmt.Errorf("Unable to create private key from Yubikey authentication (9a) slot: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(srvAddr)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  pk,
				},
			},
			RootCAs: caCertPool,
		},
	}

	server := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", proxyPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
		}),
	}

	fmt.Printf("Proxy running on localhost: %d\n", proxyPort)
	return server.ListenAndServe()
}
