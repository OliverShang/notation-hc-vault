package crypto

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"log"
	"testing"
	"time"
)

func TestWrappingKey(t *testing.T) {
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
	resp, err := client.Secrets.TransitReadWrappingKey(ctx)
	data := resp.Data["public_key"].(string)
	fmt.Println(data)
}
