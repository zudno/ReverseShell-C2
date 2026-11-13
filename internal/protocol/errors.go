package protocol

// Wire error codes (README §4.4).
const (
	ErrCodeBadFrame        = "BAD_FRAME"
	ErrCodeBadEnvelope     = "BAD_ENVELOPE"
	ErrCodeMsgTooLarge     = "MSG_TOO_LARGE"
	ErrCodeUnknownType     = "UNKNOWN_TYPE"
	ErrCodeUnknownSession  = "UNKNOWN_SESSION"
	ErrCodeAuthFailed      = "AUTH_FAILED"
	ErrCodeUnsupportedKind = "UNSUPPORTED_KIND"
	ErrCodeInternal        = "INTERNAL"
)
