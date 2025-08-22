package joinv1

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/gravitational/trace"
	grpc "google.golang.org/grpc"

	joinv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/join/v1"
	"github.com/gravitational/teleport/lib/join/messages"
)

type Client struct {
	grpcClient joinv1.JoinServiceClient
}

func NewClient(cc grpc.ClientConnInterface) *Client {
	return &Client{
		grpcClient: joinv1.NewJoinServiceClient(cc),
	}
}

func (c *Client) Join(ctx context.Context) (*messages.ClientStream, error) {
	ctx, cancel := context.WithCancelCause(ctx)

	grpcStream, err := c.grpcClient.Join(ctx)
	if err != nil {
		cancel(err)
		return nil, trace.Wrap(err)
	}

	serverStream, clientStream := messages.MessageStreams(ctx)

	var closeOnce sync.Once
	closeStreams := func(err error) {
		closeOnce.Do(func() {
			cancel(err)
		})
	}

	go func() (err error) {
		defer func() {
			if err != nil {
				closeStreams(err)
			} else {
				grpcStream.CloseSend()
			}
		}()
		for {
			msg, err := serverStream.Recv(ctx)
			if errors.Is(err, io.EOF) {
				return nil
			}
			req, err := requestFromMessage(msg)
			if err != nil {
				return trace.Wrap(err)
			}
			if err := grpcStream.Send(req); err != nil {
				return trace.Wrap(err, "sending request to gRPC stream")
			}
		}
	}()
	go func() (err error) {
		defer func() {
			if err != nil {
				closeStreams(err)
			} else {
				serverStream.CloseSend()
			}
		}()
		for {
			resp, err := grpcStream.Recv()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return trace.Wrap(err, "reading response from gRPC stream")
			}
			msg, err := responseToMessage(resp)
			if err != nil {
				return trace.Wrap(err)
			}
			if err := serverStream.Send(ctx, msg); err != nil {
				return trace.Wrap(err)
			}
		}
	}()

	return clientStream, nil
}
