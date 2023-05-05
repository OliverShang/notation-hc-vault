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
	notationx509 "github.com/notaryproject/notation-core-go/x509"
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
	//	privateKeyString := `-----BEGIN RSA PRIVATE KEY-----
	//MIIEowIBAAKCAQEApx8OlFrFfiHzFK5T5z78pA1fge4vMt2o7oNe2FjtuYpEdPXV
	//MwBt2e+4Yt1AQ9vXMzYEHxcs69eY6rfJx0iyg/DR6eNLkHfebGjel82kWVfuhl4r
	//tEmGe8MlKD6Y21+rSpLEItkaGHCNZdi3vfFWQZvUIhPdO4eZNYMSW9I60F/bkzeI
	//SQ7ZSGzUfzjYJUHnAV8bPNH63I18rWd34TzXWdIQCX2lhSQGPR4zMxHqUKgC4RUq
	//MjUWwqqgUb1BG/beIfMEVT84uAEeeMCQWnIuNDfuFmEwazkkDjrsD/Lmed0Ij+Te
	//GC0FkTupaNwvAuvLcF9pUc29WrgxTaYiaFsF1QIDAQABAoIBAA5EdX8u3KtvBIyg
	//cWNNmk37Iks6ZWcnS1PJfWBk/y6W4k9F6YSoJbi0YX53OxRQAWhK1UE+PkSILHLl
	//a+GKkEr5VUJteDcGNMP2lAJLuRsziZaJFZwXptaMC3ELHwujeEEulHYRKMwrV7b5
	//MH6TyvRg9FRQc9OwOOE7pmaWZRUC5qKtVk9WLhzqRNdHMJ7Q83GXCeNu74wUbuUj
	//I10PpBtzHYpPccYAlXIJzRtz1T66/KjMF8Jwjy0A3OMVZ37Kk7lLAxNkr1lg/3JP
	//MOnDpGbhGWoa9PxP7T7ZG6wSg3h+NtblRSVw5VVmooWC8kq6gC+CBiJ1xe49tzd6
	//0/40TQUCgYEA2kvilZJAGt/xQOu7I7dJSzTVmEVty0EEkvOgcNYysPKtGXzGF0tu
	//XBSdQX2k3Zgx9MBa0RVuK0gB2gQ+w8Wwub2hKSkyNyUsVJZiUPGSREHRv1tHwn2D
	//75ZoA+5OcQ/nZTYOmOyIjjcw+3bDSLFaroZ/m0HZu/IQ3f5fs/w03fcCgYEAw/xu
	//klKsRQPw8xZ8kMk5+xUJd4GIvsZRF8Zng3zsieqK/1xmeT/HWfd9GBXtIdVp3dH+
	//opIf1vSA4ZNB4iBquQKwvETQtnDRuyMVHuzxwDG/QR10tO2ezh/GWJbbzCpUG3QB
	//AOrCfe1If4sUvrWkkBQwKtTjMgu9uXjRmMpMt5MCgYEAj3RnBtwBfKfGJ1/Cr4n3
	//hJDH/TVDHdswYlHwEbbxwQ75alJw60YK1EBHx44GFgm6apkuFVD8AT1k2h0IEieM
	//J8PScPY9pbesFjptibv23xxR9mrKEaniVkSFPnAQ5IQLEJwho6VtZ+glLFuzocXL
	//Tf3dRe5UZAqDwx8zTVhkdakCgYAG1tVI9+eZFPUgloVMTClg0LAe4n9SIPuNd9f+
	//56odefjVxnSxAH/FbPSJlaJLzvW9zuky5SSFTMz+kjP3Xyg6QpTGTSR3aWJ4RFYl
	//WSFqkpHZBN0gvzYOfV9fkgwjiMqclqS+UnLtEA26nbDgotgWSw4PQJSZF33MbiHq
	//UgzxTwKBgA+k88u67S9gRqcbYqWmyFHha9lqrxg2UjbOXBvc9YpUwDytfRe5ziAW
	//4GJHHDVlJJT5k9etev6T33WMsPUn5vw/gEMLUlojbyNg6KoYWZAXZR6Un9QjQYGR
	//lAgfu+Heic94dkZuWbB7MuVYisnphbl9fIPpkTK+JUKDqv7Sd7kk
	//-----END RSA PRIVATE KEY-----`
	privateKeyPath := "C:\\Users\\creep\\vault\\openssl\\leaf.key"
	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	//privateKeyBlock, _ := pem.Decode([]byte(privateKeyString))
	//privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	privateKey, err := notationx509.ReadPrivateKeyFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
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
	wrappedTargetKey, err := wrapKWP.Wrap(pkcs8PrivateKey)
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
