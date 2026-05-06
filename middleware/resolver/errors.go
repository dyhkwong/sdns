package resolver

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/util"
)

// Network and authority errors. DNSSEC-specific sentinels live in
// the dnssec package.
var (
	errMaxDepth = &util.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Maximum recursion depth exceeded",
	}
	errParentDetection = &util.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Delegation loop detected",
	}
	errNoReachableAuth = &util.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "No reachable authoritative servers",
	}
	errConnectionFailed = &util.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "All authoritative servers failed",
	}
	errNoRootServers = &util.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: "Unable to reach root servers",
	}
)

// NewNetworkError creates a network error with EDE information.
func NewNetworkError(err error) *util.EDEError {
	return &util.EDEError{
		Code:    dns.ExtendedErrorCodeNetworkError,
		Message: "network error",
		Err:     err,
	}
}

// NewNoReachableAuthorityError creates an error for unreachable servers.
func NewNoReachableAuthorityError(message string) *util.EDEError {
	return &util.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: message,
	}
}

// NoReachableAuthAtZone creates an error with zone context.
func NoReachableAuthAtZone(zone string) *util.EDEError {
	return &util.EDEError{
		Code:    dns.ExtendedErrorCodeNoReachableAuthority,
		Message: fmt.Sprintf("at delegation %s", zone),
	}
}
