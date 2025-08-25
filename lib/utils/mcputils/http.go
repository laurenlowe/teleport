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

package mcputils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/gravitational/trace"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gravitational/teleport/lib/utils"
)

// ResponseProcessor defines a function that process a JSON RPC response from
// the server and returns the message that needs to be sent to the client.
type ResponseProcessor func(context.Context, *JSONRPCResponse) mcp.JSONRPCMessage

// ReplaceHTTPResponse handles replacing the MCP server response for the
// streamable HTTP transport.
//
// https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http
func ReplaceHTTPResponse(ctx context.Context, resp *http.Response, processResponse ResponseProcessor, log *slog.Logger) error {
	// Nothing to replace.
	if resp.StatusCode != http.StatusOK || resp.ContentLength == 0 {
		return nil
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return trace.Wrap(err)
	}
	switch mediaType {
	case "application/json":
		log.DebugContext(ctx, "Replacing HTTP response body in JSON")
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return trace.Wrap(err)
		}
		respFromServer, err := UnmarshalResponse(string(respBody))
		if err != nil {
			return trace.Wrap(err)
		}
		respToClient := processResponse(ctx, respFromServer)
		respToClientAsBody, err := json.Marshal(respToClient)
		if err != nil {
			return trace.Wrap(err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(respToClientAsBody))
		return nil

	case "text/event-stream":
		// Multiple messages can be sent through SSE. Instead of reading all
		// messages then replacing them, here we replace the body with a reader
		// that process the event one a time.
		log.DebugContext(ctx, "Replacing HTTP response body in SSE")
		resp.Body = &httpSSEResponseReplacer{
			ctx:               ctx,
			SSEResponseReader: NewSSEResponseReader(resp.Body),
			processResponse:   processResponse,
		}
		return nil
	default:
		return trace.BadParameter("unsupported response type %s", mediaType)
	}
}

type httpSSEResponseReplacer struct {
	*SSEResponseReader
	ctx             context.Context
	processResponse ResponseProcessor
	buf             []byte
}

func (r *httpSSEResponseReplacer) Read(p []byte) (int, error) {
	if len(r.buf) != 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	msg, err := r.ReadMessage(r.ctx)
	if err != nil {
		if utils.IsOKNetworkError(err) {
			return 0, io.EOF
		}
		return 0, trace.Wrap(err)
	}

	respFromServer, err := UnmarshalResponse(msg)
	if err != nil {
		return 0, trace.Wrap(err)
	}
	respToClient := r.processResponse(r.ctx, respFromServer)
	respToSendAsBody, err := json.Marshal(respToClient)
	if err != nil {
		return 0, trace.Wrap(err)
	}

	// Convert to SSE.
	r.buf = []byte(fmt.Sprintf("event: message\ndata: %s\n\n", string(respToSendAsBody)))
	return r.Read(p)
}
