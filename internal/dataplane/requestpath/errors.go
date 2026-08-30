package requestpath

import "errors"

var (
	ErrHeadTooLarge       = errors.New("requestpath: request head exceeds max_header_bytes")
	ErrPipelined          = errors.New("requestpath: pipelined request")
	ErrUnsupportedProto   = errors.New("requestpath: unsupported protocol version")
	ErrAmbiguousFraming   = errors.New("requestpath: ambiguous message framing")
	ErrBadTarget          = errors.New("requestpath: malformed request target")
	ErrUnhonourableExpect = errors.New("requestpath: unsupported Expect value")
	ErrDeniedTrailer      = errors.New("requestpath: denied trailer declaration")
	ErrNoHandoverTLS      = errors.New("requestpath: handover carried no TLS connection")
)
