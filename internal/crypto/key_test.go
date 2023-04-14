package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/google/tink/go/kwp/subtle"
	"testing"
)

func TestImportKey(t *testing.T) {
	wrappingKeyString := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3nstVb5BgsCnkQXACqn6
CJvZ80ZzsgHDvt24dGA5zQn33atO3s1e1P/9KTe2fZlxQZI3tAa+YlDkGPVEl/rW
IKVo4/PqgA9/IOr05nk69BINTQCvjFOKHZercTx9eUD7xavJmrVaRbwP1N2q6J0n
M7RIG7XQHhMvEod9fhWlXJfTLBME+Sya0JJBpEFefr3GPHwlLiERbGzNQyOseUx+
MWM6oDmTDBaOU3aY/ra8QIUYJgQunVub/BVW53HIPl3w5bquQwRy7wbMsmHJQ6Ax
jS+3zFGaepE/K2ICwjr4bwQw/MGbhz9EEjN6dtW9YXWsbSHtrXXgUUbE27DEjNPx
GQgZ8hat5kB6mlJ31Eeod0DYUEGMKBhKxvpa5QrZSpd/2nkGAf790NFm5sTVB7IN
41ZAvoKQkWBfFz5RkKh0v7YHlygaN20ymWrTk5DtBmZLGpe7ZBKsW/F+fVcu5Log
fW1q/oomon8nLJED50PijuWhlN388hAGR+4y8exEszMr8dvR5y+/mS1Vatmg84dy
sp6X9HvsAvdtZ9GiiE3n4C0XDa/NIDmZX0YGhILWBTaQxplOWjsOdm5W+qem1qq2
ysMvi+wOda6wRjdWCVkc1BYhtPOm7N9BYW9n0ICEdkgdGMCNPRBwYbv1DFoQsi39
PleKNglAUhgxDk2TfMVOr7cCAwEAAQ==
-----END PUBLIC KEY-----`
	privateKeyString := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0X4i6Kuknpw5Y
gmOP5MSDkJlqkOl1hvpmIuD34+C9TpBvT0Udnxb+s2rxcC4VIFSvi5su5V32TuTe
VgYWOacnPe2pUtkAz6/4XnkRBQda/Qe2GD95C3FI7r0gZoZIqzx/sfFKr1ejpoyj
R6YZuuiN3ZwUQ+s8BVH7uhHxFNVXXN7hK4dT0zd0ETuVD+YFERQoDE68T8gsqpQA
p3+uBYjyEe9tGEVwBxUHuzHY5lBNcpK5VoznBAYhVV6T5ze7axcb2OvyseL+D9GJ
XIrFbUw8d/J6WyKbfpxGSonnUgAbtXGlBZpG1g79ortiLU9Z0deis9y8N3N0NAYg
e0tHMkuJAgMBAAECggEASjKOXP6v4Ibg6NniONwDVpeR9Htd/eGjeYZZgr9zwIvj
8FXseY3q+KU3lc/utPQSwg+sq3Lg3yR/E1LRuCzJLORVsnSJHcNRgNrj9HNcHjq+
BFMfMRza4gSLOhvSm2wNO/4n4vAUHhax/azIkAcKCOmjfdaempcZrXJSVRib1g6F
uwiPGEaKvpPBmxqyJoMHb2W+eJwQaPwqkap6qvq2y5ZfMjiiGBdaupGofeOHivWL
nB9LQpnDa5W0wc/+enABB+0mdqRBx4RZJaFS9FOKqnGjuGXljeR1yLnXgZ78kEu/
BqCQJ/TKBwVPX0m67dyDPaheervLZuKCqKz6mZkWrQKBgQDnmvY3pCCzrbVwA2+P
C4GHHmiaA30MJe82YoXx+gBCmleWw8Cpk7q9co7JmKdOeOXMedylJQq0IV8FJVx7
TAZ3DhJyVcHGcEpnvmaKt15AO2xKtpQRUtUDrplH/lxBCYqkyA1e0QqcrzfWGtBG
Ol8XtYtsUW6rVUJai17dipcmbwKBgQDHXyRIrg7X3CMty7gpnGd8/EvI3nDcK2Fv
Ku+SzFOUgpTSEglBUdpr55geYI0Mw9E5lpyK76/cHUs/uyD1XlMIy1SsJvao4ukB
0BpuMRMv6u+o7EMkM6EBXlmn0zqIbcpKVDat6zZI+POE15rtiBku82tiSUe4vZVY
jttQCZ7phwKBgAdveigfJM2f7gtCkPpOrEHiQAlxwzn4nc1pLFOwawG4Ysd8UVsg
WwZp/xuJwxVJ3FbMMsE6hzVxPNO1d1qd/jckRINXLXlpcXoTKseZS3VUcw2S/v3v
YtdTa6hcCiosXD8eDQ/WNjkBhxFgmv8mMJdaRLedhagKfK7bepgyMtgRAoGAT3ab
VqCRZ/Xky5b78xHUqZtBdXE7WHWt4wog7Mils3aMbGIl8DP4s7NeDRV8go71sFdY
U4QO+tNuL5udGk8bF1E7kVYCT/QI3OEd97d1p06jcReh9ybg0FPTtjFZjhD8ZL3G
AXHTdChNny/0HyJ0ryL0NPtyK67cfKyLuw3qmbcCgYEA2a2Q2Im2+4PojE8lAkaP
jLFFI+I3j+jVYlR3thngf6XdaZO5qwOQaRIHleNsThONOm4SKkfMnxe8XNkSa1yS
+mrZ154+XRt7hCvRp2JAvUuPom0Ixk3FjRENAy02wpQ+hKLZ+brG/Og+45FXFVC9
MxV3oPpY1uAoIQ2Mo1bmsa8=
-----END PRIVATE KEY-----`
	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyString))
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		fmt.Print(err)
	}
	ephemeralAESKey := make([]byte, 32)
	_, err = rand.Read(ephemeralAESKey)
	if err != nil {
		fmt.Print(err)
	}
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		fmt.Print(err)
	}
	wrappedTargetKey, err := wrapKWP.Wrap(privateKeyBlock.Bytes)
	if err != nil {
		fmt.Print(err)
	}

	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		parsedKey.(*rsa.PublicKey),
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		fmt.Print(err)
	}
	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	base64Ciphertext := base64.StdEncoding.EncodeToString(combinedCiphertext)
	fmt.Print(base64Ciphertext, "\n")
}
