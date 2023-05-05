package crypto_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/OliverShang/notation-hc-vault/internal/keyvault"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"log"
	"strings"
	"testing"
	"time"
)

// computeHash computes the digest of the message with the given hash algorithm.
func computeHash(message []byte) []byte {
	hash := crypto.SHA256
	//if !hash.Available() {
	//	return nil, errors.New("unavailable hash function: " + hash.String())
	//}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

func TestSign(t *testing.T) {
	ctx := context.Background()

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress("http://127.0.0.1:8200"),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	// authenticate with a root token (insecure for dev)
	if err := client.SetToken("root"); err != nil {
		log.Fatal(err)
	}
	msg := []byte("helloworld")
	hashedMsg := computeHash(msg)
	encodedMsg := base64.StdEncoding.EncodeToString(hashedMsg)

	resp, err := client.Secrets.TransitSign(ctx, "alpine", schema.TransitSignRequest{
		Input:               encodedMsg,
		MarshalingAlgorithm: "asn1",
		KeyVersion:          0,
		Prehashed:           true,
		SaltLength:          "hash",
		SignatureAlgorithm:  "pss",
	})
	sig := resp.Data["signature"].(string)
	items := strings.Split(sig, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(items[2])
	if err != nil {
		panic(err)
	}
	vaultClient, err := keyvault.NewVaultClientFromKeyID("alpine")
	if err != nil {
		panic(err)
	}
	certs, err := vaultClient.GetCertificateChain(ctx)
	if err != nil {
		panic(err)
	}
	cert := certs[0]
	publicKey := cert.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashedMsg, sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	fmt.Println(err)
}
