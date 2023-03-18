package main

import (
	"github.com/OliverShang/notation-hc-vault/internal/version"
	"github.com/notaryproject/notation-go/plugin/proto"
)

func runGetMetadata() *proto.GetMetadataResponse {
	return &proto.GetMetadataResponse{
		Name:                      "hc-vault",
		Description:               "Sign artifacts with keys in HashiCorp Vault",
		Version:                   version.GetVersion(),
		URL:                       "https://github.com/OliverShang/notation-hc-vault",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}
}
