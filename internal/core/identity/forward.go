package identity

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// MaxForwardToLen is the longest forward target a record may carry: the RFC 5321 path limit,
// less the angle brackets.
const MaxForwardToLen = 254

// ErrInvalidForwardTo is returned for a forward target that is not one bare address, or that
// points the record at itself.
var ErrInvalidForwardTo = errors.New("identity: invalid forward_to")

// ValidateForwardTo checks a record's forward target. Empty is valid (no forward). Otherwise it
// must be one bare address (no display name, no angle brackets, nothing a header could be built
// around) of at most MaxForwardToLen bytes, and not the record's own address. Whether it names one
// of the owner's aliases is a deployment's question, not the record's: the record does not know
// them.
func ValidateForwardTo(address, target string) error {
	if target == "" {
		return nil
	}
	if len(target) > MaxForwardToLen {
		return fmt.Errorf("%w: %d bytes, at most %d", ErrInvalidForwardTo, len(target), MaxForwardToLen)
	}
	a, err := mail.ParseAddress(target)
	if err != nil || a.Name != "" || a.Address != target {
		return fmt.Errorf("%w: %q is not a bare address", ErrInvalidForwardTo, target)
	}
	if strings.EqualFold(target, address) {
		return fmt.Errorf("%w: %q forwards to itself", ErrInvalidForwardTo, target)
	}
	return nil
}
