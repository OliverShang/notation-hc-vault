package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/OliverShang/notation-hc-vault/internal/signature"
	"github.com/notaryproject/notation-go/plugin/proto"
	"io"
)

func runSign(ctx context.Context, input io.Reader) (*proto.GenerateSignatureResponse, error) {
	var req proto.GenerateSignatureRequest
	if err := json.NewDecoder(input).Decode(&req); err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}

	return signature.Sign(ctx, &req)
}
