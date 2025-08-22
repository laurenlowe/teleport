package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/join/messages"
	"github.com/gravitational/teleport/lib/utils/hostid"
	logutils "github.com/gravitational/teleport/lib/utils/log"
)

var log = logutils.NewPackageLogger(teleport.ComponentKey, "join.server")

type AuthService interface {
	RegisterUsingToken(ctx context.Context, req *types.RegisterUsingTokenRequest) (certs *proto.Certs, err error)
}

type JoinServer struct {
	authService AuthService
}

func NewJoinServer(authService AuthService) *JoinServer {
	return &JoinServer{
		authService: authService,
	}
}

func (s *JoinServer) Join(ctx context.Context) (*messages.ClientStream, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	serverStream, clientStream := messages.MessageStreams(ctx)

	go func() {
		if err := s.handleJoin(ctx, serverStream); err != nil {
			log.WarnContext(ctx, "Join attempt failed", "error", err)
			cancel(err)
		}
	}()

	return clientStream, nil
}

func (s *JoinServer) handleJoin(ctx context.Context, stream *messages.ServerStream) error {
	log.DebugContext(ctx, "Handling join request")

	msg, err := stream.Recv(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	clientInit, ok := msg.(messages.ClientInit)
	if !ok {
		return trace.BadParameter("first message on join stream was not ClientInit, got %T", msg)
	}
	log.DebugContext(ctx, "Received ClientInit",
		"method", clientInit.JoinMethod,
		"node_name", clientInit.NodeName,
	)
	if clientInit.JoinMethod != nil && types.JoinMethod(*clientInit.JoinMethod) != types.JoinMethodToken {
		return trace.BadParameter("only the token join method is current supported, client requested %s", *clientInit.JoinMethod)
	}
	joinMethod := types.JoinMethodToken

	hostID, err := hostid.Generate(ctx, joinMethod)
	if err != nil {
		return trace.Wrap(err)
	}

	tlsPub, err := x509.ParsePKIXPublicKey(clientInit.PublicTLSKey)
	if err != nil {
		return trace.Wrap(err)
	}
	tlsPubPEM, err := keys.MarshalPublicKey(crypto.PublicKey(tlsPub))
	if err != nil {
		return trace.Wrap(err)
	}
	sshPub, err := ssh.ParsePublicKey(clientInit.PublicSSHKey)
	if err != nil {
		return trace.Wrap(err)
	}

	req := &types.RegisterUsingTokenRequest{
		HostID:               hostID,
		NodeName:             clientInit.NodeName,
		Role:                 types.SystemRole(clientInit.Role),
		Token:                clientInit.TokenName,
		AdditionalPrincipals: clientInit.AdditionalPrincipals,
		DNSNames:             clientInit.DNSNames,
		PublicTLSKey:         tlsPubPEM,
		PublicSSHKey:         ssh.MarshalAuthorizedKey(sshPub),
		Expires:              clientInit.Expires,
		// RemoteAddr:
		// EC2IdentityDocument
		// IDToken
		// BotInstanceID
		// BotGeneration
		// PreviousBotInstanceID
	}
	certs, err := s.authService.RegisterUsingToken(ctx, req)
	if err != nil {
		return trace.Wrap(err)
	}

	sshCert, err := rawSSHCert(certs.SSH)
	if err != nil {
		return trace.Wrap(err)
	}
	sshCAKeys, err := rawSSHPublicKeys(certs.SSHCACerts)
	if err != nil {
		return trace.Wrap(err)
	}

	result := messages.Result{
		TLSCert:    rawTLSCert(certs.TLS),
		TLSCACerts: rawTLSCerts(certs.TLSCACerts),
		SSHCert:    sshCert,
		SSHCAKeys:  sshCAKeys,
		HostID:     hostID,
	}
	if err := stream.Send(ctx, result); err != nil {
		return trace.Wrap(err)
	}
	stream.CloseSend()

	return nil
}

func rawTLSCerts(pemBytes [][]byte) [][]byte {
	out := make([][]byte, len(pemBytes))
	for i, bytes := range pemBytes {
		out[i] = rawTLSCert(bytes)
	}
	return out
}

func rawTLSCert(pemBytes []byte) []byte {
	pemBlock, _ := pem.Decode(pemBytes)
	return pemBlock.Bytes
}

func rawSSHCert(authorizedKey []byte) ([]byte, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return pub.Marshal(), nil
}

func rawSSHPublicKeys(authorizedKeys [][]byte) ([][]byte, error) {
	out := make([][]byte, len(authorizedKeys))
	for i, authorizedKey := range authorizedKeys {
		var err error
		out[i], err = rawSSHCert(authorizedKey)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return out, nil
}
