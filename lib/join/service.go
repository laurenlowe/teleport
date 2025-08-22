package join

import (
	"context"

	"github.com/gravitational/teleport/lib/join/messages"
)

type Service interface {
	Join(context.Context) (*messages.ClientStream, error)
}
