/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib/reverseproxy"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"
	listenerutils "github.com/gravitational/teleport/lib/utils/listener"
	"github.com/gravitational/teleport/lib/utils/mcputils"
)

func (s *Server) handleStreamableHTTP(ctx context.Context, sessionCtx *SessionCtx) error {
	s.cfg.Log.WarnContext(ctx, "=== handleStreamableHTTP")
	// TODO(greedy52) cache session similar to how app access handles chunks for
	// recording purpose.
	session, err := s.makeSessionHandler(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err, "setting up session handler")
	}

	transport, err := s.makeStreamableHTTPTransport(ctx, session)
	if err != nil {
		return trace.Wrap(err, "setting up streamable http transport")
	}

	proxy, err := reverseproxy.New(
		reverseproxy.WithFlushInterval(100*time.Millisecond),
		reverseproxy.WithRoundTripper(transport),
		reverseproxy.WithLogger(session.logger),
	)
	if err != nil {
		return trace.Wrap(err, "creating reverse proxy")
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			proxy.ServeHTTP(w, req)
		}),
	}
	err = server.Serve(
		listenerutils.NewSingleUseListener(sessionCtx.ClientConn),
	)
	if err != nil && !utils.IsOKNetworkError(err) {
		s.cfg.Log.WarnContext(ctx, "=== handleStreamableHTTP done", "err", err)
		return trace.Wrap(err)
	}
	s.cfg.Log.WarnContext(ctx, "=== handleStreamableHTTP before shutdown", "err", err)
	server.Shutdown(ctx)
	s.cfg.Log.WarnContext(ctx, "=== handleStreamableHTTP after shutdown", "err", err)
	return nil
}

func (s *Server) makeStreamableHTTPTransport(ctx context.Context, session *sessionHandler) (http.RoundTripper, error) {
	targetURI, err := url.Parse(session.App.GetURI())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	targetURI.Scheme = strings.TrimPrefix(targetURI.Scheme, "mcp+")

	tr, err := defaults.Transport()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &sessionTransport{
		sessionHandler: session,
		targetURI:      targetURI,
		tr:             tr,
	}, nil
}

type sessionTransport struct {
	*sessionHandler
	targetURI *url.URL
	tr        http.RoundTripper
}

type respBodyReadCloser struct {
	*sessionHandler
	messageReader *mcputils.SSEResponseReader
	buf           []byte
}

func makeRespBodyReader(session *sessionHandler, respBody io.ReadCloser) io.ReadCloser {
	return &respBodyReadCloser{
		sessionHandler: session,
		messageReader:  mcputils.NewSSEResponseReader(respBody),
	}
}

func (r *respBodyReadCloser) Read(p []byte) (int, error) {
	if len(r.buf) != 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	msg, err := r.messageReader.ReadMessage(context.TODO())
	if err != nil {
		if utils.IsOKNetworkError(err) {
			return 0, io.EOF
		}
		return 0, trace.Wrap(err)
	}
	respReceived, err := mcputils.UnmarshalResponse(msg)
	if err != nil {
		r.logger.DebugContext(context.TODO(), "==== jrpc unmarshal error", "err", err)
		return 0, trace.Wrap(err)
	}
	r.logger.DebugContext(context.TODO(), "==== marshal SSE response", "event", respReceived)
	respToSend := r.sessionHandler.processServerResponse(context.TODO(), respReceived)
	// TODO move to mcputils
	respToSendAsBody, err := json.Marshal(respToSend)
	if err != nil {
		r.logger.DebugContext(context.TODO(), "==== json marshal error", "err", err)
		return 0, trace.Wrap(err)
	}
	r.buf = []byte(fmt.Sprintf("event: message\ndata: %s\n\n", string(respToSendAsBody)))
	return r.Read(p)
}

func (r *respBodyReadCloser) Close() error {
	return r.messageReader.Close()
}

func (t *sessionTransport) setExternalSessionID(id string) {
	if id == "" {
		return
	}

	// Store the external session ID.
	t.sessionCtx.mcpSessionID.Store(&id)

	// Use the external session ID for our session ID, if it's already a UUID.
	// If not, do a UUID hash.
	if parsedID, err := uuid.Parse(id); err == nil {
		t.sessionID = session.ID(parsedID.String())
	} else {
		t.sessionID = session.ID(uuid.NewSHA1(uuid.Nil, []byte(id)).String())

	}
}

func (t *sessionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.setExternalSessionID(r.Header.Get("Mcp-Session-Id"))

	r.URL.Scheme = t.targetURI.Scheme
	r.URL.Host = t.targetURI.Host

	// Defaults to the endpoint defined in the app if client is not providing it.
	if t.targetURI.Path != "" {
		r.URL.Path = t.targetURI.Path
	}

	t.logger.DebugContext(r.Context(), "=== round trip", "uri", r.URL.String(), "accept", r.Header.Values("Accept"))
	defer t.logger.DebugContext(r.Context(), "=== round trip done")

	reqBody, err := utils.GetAndReplaceRequestBody(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if body, err := httputil.DumpRequest(r, true); err == nil {
		t.logger.DebugContext(r.Context(), "=== request dump", "body", string(body))
	}

	var initReq *mcputils.JSONRPCRequest
	switch {
	case r.Method == http.MethodDelete:
		t.emitEndEvent(t.parentCtx)
		return t.tr.RoundTrip(r)
	case len(reqBody) > 0:
		var baseMessage mcputils.BaseJSONRPCMessage
		if err := json.Unmarshal(reqBody, &baseMessage); err != nil {
			return nil, trace.Wrap(err)
		}
		switch {
		case baseMessage.IsRequest():
			req := baseMessage.MakeRequest()
			switch req.Method {
			case "initialize":
				// TODO(greedy52) handle this in a more automatic way
				initReq = req
			default:
				errResp, replyDir := t.sessionHandler.processClientRequest(r.Context(), req)
				errRespAsBody, err := json.Marshal(errResp)
				if err != nil {
					return nil, trace.Wrap(err)
				}
				if replyDir == replyToClient {
					t.logger.WarnContext(r.Context(), "=== blocking request", "accept", r.Header.Get("accept"))
					httpResp := &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(errRespAsBody)),
						Header:     make(http.Header),
					}
					httpResp.Header.Set("Content-Type", "application/json")
					httpResp.Header.Set("Mcp-Session-Id", r.Header.Get("Mcp-Session-Id"))
					return httpResp, nil
				}
			}
		case baseMessage.IsNotification():
			t.sessionHandler.processClientNotification(r.Context(), baseMessage.MakeNotification())
		default:
			return nil, trace.BadParameter("todo something went wrong")
		}
	}

	resp, err := t.tr.RoundTrip(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if initReq != nil {
		t.setExternalSessionID(resp.Header.Get("Mcp-Session-Id"))
		t.emitStartEvent(t.parentCtx)
		t.emitRequestEvent(t.parentCtx, initReq, nil)
	}

	if err := mcputils.ReplaceHTTPResponse(
		r.Context(),
		resp,
		t.sessionHandler.processServerResponse,
		t.logger,
	); err != nil {
		return nil, trace.Wrap(err)
	}
	return resp, nil
}
