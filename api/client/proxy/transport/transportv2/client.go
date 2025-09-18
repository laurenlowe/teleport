// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transportv2

import (
	"context"
	"net"
	"sync"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh/agent"

	transportv2pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/transport/v2"
	streamutils "github.com/gravitational/teleport/api/utils/grpc/stream"
)

// Client is a wrapper around a [transportv2.TransportServiceClient] that
// hides the implementation details of establishing connections
// over gRPC streams.
type Client struct {
	clt transportv2pb.TransportServiceClient
}

// NewClient constructs a Client that operates on the provided
// [transportv2pb.TransportServiceClient]. An error is returned if the client
// provided is nil.
func NewClient(client transportv2pb.TransportServiceClient) (*Client, error) {
	if client == nil {
		return nil, trace.BadParameter("parameter client required")
	}

	return &Client{clt: client}, nil
}

// DialHost establishes a connection to the instance in the provided cluster that matches
// the hostport. If a keyring is provided then it will be forwarded to the remote instance.
// The src address will be used as the LocalAddr of the returned [net.Conn].
func (c *Client) DialHost(ctx context.Context, hostport, cluster string, src net.Addr, keyring agent.ExtendedAgent) (net.Conn, *transportv2pb.ClusterDetails, error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := c.clt.ProxySSH(ctx)
	if err != nil {
		cancel()
		return nil, nil, trace.Wrap(err, "unable to establish proxy stream")
	}

	// TODO(cthach): Wait to see if MFA is required and if so handle it.

	if err := stream.Send(&transportv2pb.ProxySSHRequest{
		Payload: &transportv2pb.ProxySSHRequest_DialTarget{
			DialTarget: &transportv2pb.TargetHost{
				HostPort: hostport,
				Cluster:  cluster,
			},
		},
	}); err != nil {
		cancel()
		return nil, nil, trace.Wrap(err, "failed to send dial target request")
	}

	resp, err := stream.Recv()
	if err != nil {
		cancel()
		return nil, nil, trace.Wrap(err, "failed to receive cluster details response")
	}

	// create streams for ssh and agent protocol
	sshStream, agentStream := newSSHStreams(stream, cancel)

	// create a reader writer for agent protocol
	agentRW, err := streamutils.NewReadWriter(agentStream)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	// create a reader writer for SSH protocol
	sshRW, err := streamutils.NewReadWriter(sshStream)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	sshConn := streamutils.NewConn(sshRW, src, addr(hostport))

	// multiplex the frames to the correct handlers1
	var serveOnce sync.Once
	go func() {
		defer func() {
			// closing the agentRW will terminate the agent.ServeAgent goroutine
			agentRW.Close()
			// closing the connection will close sshRW and end the connection for
			// the user
			sshConn.Close()
		}()

		for {
			req, err := stream.Recv()
			if err != nil {
				sshStream.errorC <- trace.Wrap(err)
				agentStream.errorC <- trace.Wrap(err)
				return
			}

			switch frame := req.GetPayload().(type) {
			case *transportv2pb.ProxySSHResponse_Ssh:
				sshStream.incomingC <- frame.Ssh.Payload
			case *transportv2pb.ProxySSHResponse_Agent:
				if keyring == nil {
					continue
				}

				// start serving the agent only if the upstream
				// service attempts to interact with it
				serveOnce.Do(func() {
					go agent.ServeAgent(keyring, agentRW)
				})

				agentStream.incomingC <- frame.Agent.Payload
			default:
				continue
			}
		}
	}()

	return sshConn, resp.GetDetails(), nil
}

type addr string

func (a addr) Network() string {
	return "tcp"
}

func (a addr) String() string {
	return string(a)
}

// sshStream implements the [streamutils.Source] interface
// for a [transportv2pb.TransportService_ProxySSHClient]. Instead of
// reading directly from the stream reads are from an incoming
// channel that is fed by the multiplexer.
type sshStream struct {
	incomingC chan []byte
	errorC    chan error
	requestFn func(payload []byte) *transportv2pb.ProxySSHRequest
	closedC   chan struct{}
	wLock     *sync.Mutex
	stream    transportv2pb.TransportService_ProxySSHClient
	cancel    context.CancelFunc
}

func newSSHStreams(stream transportv2pb.TransportService_ProxySSHClient, cancel context.CancelFunc) (ssh *sshStream, agent *sshStream) {
	wLock := &sync.Mutex{}
	closedC := make(chan struct{})

	ssh = &sshStream{
		incomingC: make(chan []byte, 10),
		errorC:    make(chan error, 1),
		stream:    stream,
		requestFn: func(payload []byte) *transportv2pb.ProxySSHRequest {
			return &transportv2pb.ProxySSHRequest{
				Payload: &transportv2pb.ProxySSHRequest_Ssh{Ssh: &transportv2pb.Frame{Payload: payload}}}
		},
		wLock:   wLock,
		closedC: closedC,
		cancel:  cancel,
	}

	agent = &sshStream{
		incomingC: make(chan []byte, 10),
		errorC:    make(chan error, 1),
		stream:    stream,
		requestFn: func(payload []byte) *transportv2pb.ProxySSHRequest {
			return &transportv2pb.ProxySSHRequest{
				Payload: &transportv2pb.ProxySSHRequest_Agent{Agent: &transportv2pb.Frame{Payload: payload}},
			}
		},
		wLock:   wLock,
		closedC: closedC,
		cancel:  cancel,
	}

	return ssh, agent
}

func (s *sshStream) Recv() ([]byte, error) {
	select {
	case err := <-s.errorC:
		return nil, trace.Wrap(err)
	case frame := <-s.incomingC:
		return frame, nil
	}
}

func (s *sshStream) Send(frame []byte) error {
	// grab lock to prevent any other sends from occurring
	s.wLock.Lock()
	defer s.wLock.Unlock()

	// only Send if the stream hasn't already been closed
	select {
	case <-s.closedC:
		return nil
	default:
		return trace.Wrap(s.stream.Send(s.requestFn(frame)))
	}
}

func (s *sshStream) Close() error {
	s.cancel()
	// grab lock to prevent any sends from occurring
	s.wLock.Lock()
	defer s.wLock.Unlock()

	// only CloseSend if the stream hasn't already been closed
	select {
	case <-s.closedC:
		return nil
	default:
		close(s.closedC)
		return trace.Wrap(s.stream.CloseSend())
	}
}
