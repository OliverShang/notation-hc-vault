package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/notaryproject/notation-go/plugin/proto"
	"io"
)

func runDescribeKey(ctx context.Context, input io.Reader) (*proto.DescribeKeyResponse, error) {
	// parse input request
	var req proto.DescribeKeyRequest
	if err := json.NewDecoder(input).Decode(&req); err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}

	// get key spec for notation
	keySpec, err := notationKeySpec(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}

	return &proto.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: keySpec,
	}, nil
}

func notationKeySpec(ctx context.Context, keyID string) (proto.KeySpec, error) {
	return "", nil
}
