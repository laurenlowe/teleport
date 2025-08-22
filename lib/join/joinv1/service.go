package joinv1

import (
	"context"
	"errors"
	"io"

	"github.com/gravitational/trace"
	"golang.org/x/sync/errgroup"
	grpc "google.golang.org/grpc"

	joinv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/join/v1"
	"github.com/gravitational/teleport/lib/join/messages"
)

type Service interface {
	Join(context.Context) (*messages.ClientStream, error)
}

type server struct {
	joinv1.UnsafeJoinServiceServer

	service Service
}

func RegisterJoinServiceServer(s grpc.ServiceRegistrar, service Service) {
	joinv1.RegisterJoinServiceServer(s, &server{
		service: service,
	})
}

func (s *server) Join(grpcStream grpc.BidiStreamingServer[joinv1.JoinRequest, joinv1.JoinResponse]) error {
	messageStream, err := s.service.Join(grpcStream.Context())
	if err != nil {
		return trace.Wrap(err)
	}

	g, ctx := errgroup.WithContext(grpcStream.Context())
	g.Go(func() error {
		defer messageStream.CloseSend()
		for {
			req, err := grpcStream.Recv()
			if errors.Is(err, io.EOF) {
				// The client called CloseSend on the grpcStream, this is not an error.
				return nil
			}
			if err != nil {
				return trace.Wrap(err, "reading client request from gRPC stream")
			}
			msg, err := requestToMessage(req)
			if err != nil {
				return trace.Wrap(err)
			}
			if err := messageStream.Send(ctx, msg); err != nil {
				return trace.Wrap(err)
			}
		}
	})
	g.Go(func() error {
		for {
			msg, err := messageStream.Recv(ctx)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return trace.Wrap(err)
			}
			resp, err := responseFromMessage(msg)
			if err != nil {
				return trace.Wrap(err)
			}
			if err := grpcStream.Send(resp); err != nil {
				return trace.Wrap(err, "sending server response to gRPC stream")
			}
		}
	})
	return trace.Wrap(g.Wait())
}
