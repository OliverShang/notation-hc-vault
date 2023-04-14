package keyvault

import (
	"context"
	"crypto/x509"
	"github.com/OliverShang/notation-hc-vault/internal/crypto"
	"github.com/hashicorp/vault-client-go"
	"log"
	"time"
)

const vaultHost = "127.0.0.1:8200"

var ParseCertificates = crypto.ParseCertificates

type VaultClientWrapper struct {
	vaultClient *vault.Client

	keyID string
}

func NewVaultClientFromKeyID(id string) (*VaultClientWrapper, error) {
	vaultUrl := "http://" + vaultHost
	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(vaultUrl),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	// authenticate with a root token (insecure)
	if err := client.SetToken("root"); err != nil {
		log.Fatal(err)
	}

	return &VaultClientWrapper{
		vaultClient: client,
		keyID:       id,
	}, nil
}

func (vw *VaultClientWrapper) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	// read a certChain
	secret, err := vw.vaultClient.Secrets.KVv2Read(ctx, vw.keyID)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("Successfully got the cert chain from vault")
	certString := secret.Data["data"].(map[string]interface{})["certificate"].(string)
	certBytes := []byte(certString)
	certs, err := ParseCertificates(certBytes)
	return certs, nil
}
