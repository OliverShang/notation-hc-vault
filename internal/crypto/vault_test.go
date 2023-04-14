package crypto

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"log"
	"strings"
	"testing"
	"time"
)

// parseCertificates parses certificates from either PEM or DER data
// returns an empty list if no certificates are found
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	if block == nil {
		// data may be in DER format
		derCerts, err := x509.ParseCertificates(data)
		if err != nil {
			return nil, err
		}
		certs = append(certs, derCerts...)
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}
	return certs, nil
}

func TestVaultClient(t *testing.T) {
	ctx := context.Background()

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress("http://127.0.0.1:8200"),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	// authenticate with a root token (insecure)
	if err := client.SetToken("root"); err != nil {
		log.Fatal(err)
	}

	certificateString := `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIBMDANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEP
MA0GA1UEAxMGYWxwaW5lMB4XDTIzMDMyNDA2Mzk0N1oXDTIzMDMyNTA2Mzk0N1ow
TjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8w
DQYDVQQKEwZOb3RhcnkxDzANBgNVBAMTBmFscGluZTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALpA+PpuI4H0qhluNHgrB8Wbnm+/PimQF9gm2XUotEJT
WE8AvGdDLOjxerijQboZjoSGYVvJoux5LGvc8ntamR2Smv4j4xd5hIhsoAL/kHtP
R+9nLBW9g3QhtOiGeKJJ392r7Pe6gfttC2nSzBs4wol3jSO6+GFCN4CAVDKHz/CS
iXrsEaHA6Aqbl2AO69MHx5NUXvamsuUvCc/s1dVjBNfrd0YxSiLmna8Tz0UM5LC7
YOPjLCbVM5YFxinHsg39bFpO20xYs44q09CDV+KWSESx9bgXgjo3o//2b8pXGFJ0
qfgKGLS9IyByVILbpA8rBbvrZE5rBNVAblx+owhJDzkCAwEAAaMnMCUwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IB
AQBLsUVKlU72vnN9i3Mdi4+8hacby+lCt94wnNc3IOBWxCeLgA+W1p4quoAwle8r
/mKWoK6kpEoCKMZlmyfJKrgMkw7EXVWeAJbsvRDhB69La9VxLPnQX7Wo9zT7WNwG
1w6naDg6AIFVPeIJzAobaxCYBx7P0YgFOvj2Y/DJTMnTvOj2DwCMqlCsezRBTmrr
uAdTqBHlUVcmQZvIEcIXGX0myOwfeGSq42ei+UaMk4rZKJ9DPTGSrXak6t1DuAxz
yolwIT27dtyT8xSNv1xvCSO5d/APqynhbRp1YLOmMCpvYRE5AadPSr4SPeN6boqk
klbZj7vMmIqdC4i1P+BLmzmn
-----END CERTIFICATE-----`

	certificateString = strings.Replace(certificateString, "\n", "", -1)
	// write a secret
	//_, err = client.Secrets.KVv2Write(ctx, "alpine", schema.KVv2WriteRequest{
	//	Data: map[string]any{
	//		"certificate": certificateString,
	//	},
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}
	log.Println("secret written successfully")

	// read a secret
	s, err := client.Secrets.KVv2Read(ctx, "alpine")
	if err != nil {
		log.Fatal(err)
	}
	data := s.Data["data"].(map[string]interface{})
	certString := data["certificate"].(string)
	//fmt.Println(certString)
	certBytes := []byte(certString)
	certs, err := parseCertificates(certBytes)
	//block, _ := pem.Decode(certBytes)
	//cert, err := x509.ParseCertificate(block.Bytes)
	fmt.Printf("%+v", certs)
	//log.Println("secret retrieved:", s.Data)
}
