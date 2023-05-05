package crypto

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"
)

func TestImportCertChain(t *testing.T) {
	ctx := context.Background()
	certPath := "C:\\Users\\creep\\Desktop\\combined_cert.pem"
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
	file, err := os.Open(certPath)
	if err != nil {
		log.Fatal(err)
	}
	b, err := ioutil.ReadAll(file)
	fmt.Print(b)
	data := make(map[string]interface{})
	data["certificate"] = string(b)
	writePath := "anything"
	req := schema.KVv2WriteRequest{
		Data:    data,
		Options: nil,
		Version: 0,
	}
	_, err = client.Secrets.KVv2Write(ctx, writePath, req)
	if err != nil {
		fmt.Println(err)
	}
}
