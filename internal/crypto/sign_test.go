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

	resp, err := client.Secrets.TransitSign(ctx, "alpine", schema.TransitSignRequest{
		Input:               "aGVsbG8gd29ybGQ=",
		MarshalingAlgorithm: "asn1",
		KeyVersion:          0,
		Prehashed:           false,
		SaltLength:          "auto",
		SignatureAlgorithm:  "pss",
	})
	sig := resp.Data["signature"].(string)
	byte_sig := []byte(sig)

	fmt.Println(byte_sig)
	fmt.Println(resp.Data)
}
