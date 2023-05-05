package crypto

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"log"
	"testing"
	"time"
)

func TestImportPrivateKey(t *testing.T) {
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

	req := schema.TransitImportKeyRequest{
		AllowPlaintextBackup: false,
		AllowRotation:        false,
		AutoRotatePeriod:     0,
		Ciphertext:           "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",
		Context:              "",
		Derived:              false,
		Exportable:           false,
		HashFunction:         "SHA256",
		Type:                 "rsa-2048",
	}
	resp, err := client.Secrets.TransitImportKey(ctx, "anything", req)
	fmt.Println(resp.Data)
}
