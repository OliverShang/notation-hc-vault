package signature

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/OliverShang/notation-hc-vault/internal/keyvault"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/notaryproject/notation-go/plugin/proto"
	"time"
)

func Sign(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {

	// validate request
	if req == nil || req.KeyID == "" || req.KeySpec == "" || req.Hash == "" {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("invalid request input"),
		}
	}

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress("http://127.0.0.1:8200"),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to prepare a client, %v", err),
		}
	}

	// authenticate with a root token (insecure for dev)
	if err := client.SetToken("root"); err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to authenticate with a root token, %v", err),
		}
	}

	// get keySpec
	keySpec, err := proto.DecodeKeySpec(req.KeySpec)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to get keySpec, %v", err),
		}
	}

	// get hash algorithm and validate hash
	hashAlgorithm, err := proto.HashAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to get hash algorithm, %v", err),
		}
	}

	if hashAlgorithm != req.Hash {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("keySpec hash: %v mismatch request hash: %v", hashAlgorithm, req.Hash),
		}
	}

	// get signing algorithm
	signAlgorithm := getAlgorithmFromKeySpec(req.KeySpec)
	if signAlgorithm == "" {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("unrecognized key spec: " + string(req.KeySpec)),
		}
	}

	// compute hash for the payload
	hashData, err := computeHash(keySpec.SignatureAlgorithm().Hash(), req.Payload)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to compute hash for the payload, %v", err),
		}
	}
	encodedHash := base64.StdEncoding.EncodeToString(hashData)
	resp, err := client.Secrets.TransitSign(ctx, req.KeyID, schema.TransitSignRequest{
		Input:               encodedHash,
		MarshalingAlgorithm: "asn1",
		KeyVersion:          0,
		Prehashed:           true,
		SaltLength:          "auto",
		SignatureAlgorithm:  signAlgorithm,
	})

	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to sign with Transit secret engine, %v", err),
		}
	}

	signature := resp.Data["signature"].(string)

	signatureAlgorithmString, err := proto.EncodeSigningAlgorithm(keySpec.SignatureAlgorithm())
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to encode signing algorithm, %v", err),
		}
	}

	vaultClient, err := keyvault.NewVaultClientFromKeyID(req.KeyID)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to get vault client, %v", err),
		}
	}

	rawCertChain, err := getCertificateChain(ctx, *vaultClient)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to get certificate chain, %v", err),
		}
	}

	return &proto.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        []byte(signature),
		SigningAlgorithm: string(signatureAlgorithmString),
		CertificateChain: rawCertChain,
	}, nil
}

// computeHash computes the digest of the message with the given hash algorithm.
func computeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, errors.New("unavailable hash function: " + hash.String())
	}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func getAlgorithmFromKeySpec(k proto.KeySpec) string {
	switch k {
	case proto.KeySpecRSA2048:
		return "pss"
	case proto.KeySpecRSA3072:
		return "pss"
	case proto.KeySpecRSA4096:
		return "pss"
	default:
		return ""
	}
}

func getCertificateChain(ctx context.Context, vw keyvault.VaultClientWrapper) ([][]byte, error) {
	certs, err := vw.GetCertificateChain(ctx)
	if err != nil {
		return nil, err
	}
	// build raw cert chain
	rawCertChain := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCertChain = append(rawCertChain, cert.Raw)
	}
	return rawCertChain, nil
}
