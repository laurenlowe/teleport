package messages

import (
	"context"
	"io"
	"time"

	"github.com/gravitational/trace"
)

type Request interface {
	isRequest()
}

type embedRequest struct{}

func (embedRequest) isRequest() {}

type ClientInit struct {
	embedRequest

	JoinMethod              *string
	TokenName               string
	NodeName                string
	Role                    string
	AdditionalPrincipals    []string
	DNSNames                []string
	PublicTLSKey            []byte
	PublicSSHKey            []byte
	Expires                 *time.Time
	ProxySuppliedParameters *ProxySuppliedParameters
}

type ProxySuppliedParameters struct {
	RemoteAddr    string
	ClientVersion string
}

type Response interface {
	isResponse()
}

type embedResponse struct{}

func (embedResponse) isResponse() {}

type ServerInit struct {
	embedResponse

	JoinMethod string
}

type Result struct {
	embedResponse

	TLSCert    []byte
	TLSCACerts [][]byte
	SSHCert    []byte
	SSHCAKeys  [][]byte
	HostID     string
}

func MessageStreams(ctx context.Context) (*ServerStream, *ClientStream) {
	requests := make(chan Request)
	responses := make(chan Response)
	ctx, cancel := context.WithCancelCause(ctx)
	return &ServerStream{
			parentCtx:       ctx,
			cancelWithError: cancel,
			requests:        requests,
			responses:       responses,
		}, &ClientStream{
			parentCtx:       ctx,
			cancelWithError: cancel,
			requests:        requests,
			responses:       responses,
		}
}

type ServerStream struct {
	parentCtx       context.Context
	cancelWithError context.CancelCauseFunc
	requests        <-chan Request
	responses       chan<- Response
}

func (s *ServerStream) Recv(ctx context.Context) (Request, error) {
	select {
	case <-s.parentCtx.Done():
		return nil, trace.Wrap(s.parentCtx.Err())
	case <-ctx.Done():
		return nil, trace.Wrap(ctx.Err())
	case req, ok := <-s.requests:
		if !ok {
			return nil, io.EOF
		}
		return req, nil
	}
}

func (s *ServerStream) Send(ctx context.Context, response Response) error {
	select {
	case <-s.parentCtx.Done():
		return trace.Wrap(s.parentCtx.Err())
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	case s.responses <- response:
		return nil
	}
}

func (s *ServerStream) CloseSend() {
	close(s.responses)
}

func (s *ServerStream) CloseWithError(err error) {
	s.cancelWithError(err)
}

type ClientStream struct {
	parentCtx       context.Context
	cancelWithError context.CancelCauseFunc
	requests        chan<- Request
	responses       <-chan Response
}

func (s *ClientStream) Recv(ctx context.Context) (Response, error) {
	select {
	case <-s.parentCtx.Done():
		return nil, trace.Wrap(s.parentCtx.Err())
	case <-ctx.Done():
		return nil, trace.Wrap(ctx.Err())
	case resp, ok := <-s.responses:
		if !ok {
			return nil, io.EOF
		}
		return resp, nil
	}
}

func (s *ClientStream) Send(ctx context.Context, request Request) error {
	select {
	case <-s.parentCtx.Done():
		return trace.Wrap(s.parentCtx.Err())
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	case s.requests <- request:
		return nil
	}
}

func (s *ClientStream) CloseSend() {
	close(s.requests)
}

func (s *ClientStream) CloseWithError(err error) {
	s.cancelWithError(err)
}
