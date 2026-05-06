package dnssec

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/util"
)

// DNSKEY-side validation errors.
var (
	ErrNoDNSKEY = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY records found in response",
	}
	ErrMissingKSK = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No KSK DNSKEY matches DS records from parent",
	}
	ErrFailedToConvertKSK = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Unable to validate DNSKEY against parent DS record",
	}
	ErrMismatchingDS = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "DNSKEY does not match DS record from parent zone",
	}
	ErrNoSignatures = &util.EDEError{
		Code:    dns.ExtendedErrorCodeRRSIGsMissing,
		Message: "Response is missing required RRSIG records",
	}
	ErrMissingDNSKEY = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: "No DNSKEY found to validate RRSIG",
	}
	ErrInvalidSignaturePeriod = &util.EDEError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: "RRSIG validity period check failed",
	}
	ErrMissingSigned = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "RRsets covered by RRSIG are missing",
	}
	ErrDSRecords = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Parent has DS records but zone appears unsigned",
	}
	ErrTrustAnchorsUnavailable = &util.EDEError{
		Code:    dns.ExtendedErrorCodeOther,
		Message: "Trust anchors unavailable — refusing to validate",
	}
)

// NSEC / NSEC3 denial-of-existence errors.
var (
	ErrNSECTypeExists = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC record indicates queried type exists",
	}
	ErrNSECMissingCoverage = &util.EDEError{
		Code:    dns.ExtendedErrorCodeNSECMissing,
		Message: "Incomplete NSEC proof for name non-existence",
	}
	ErrNSECBadDelegation = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "Invalid NSEC type bitmap for delegation",
	}
	ErrNSECNSMissing = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC missing NS bit at delegation point",
	}
	ErrNSECOptOut = &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSBogus,
		Message: "NSEC3 opt-out validation failed",
	}
)

// DNSKEYMissingForZone returns a DNSKEY-missing error tagged with zone.
func DNSKEYMissingForZone(zone string) *util.EDEError {
	return &util.EDEError{
		Code:    dns.ExtendedErrorCodeDNSKEYMissing,
		Message: fmt.Sprintf("No DNSKEY records found for %s", zone),
	}
}

// SignatureExpiredForRRset returns a signature-expired error tagged with
// the RR type and zone.
func SignatureExpiredForRRset(rrtype, zone string) *util.EDEError {
	return &util.EDEError{
		Code:    dns.ExtendedErrorCodeSignatureExpired,
		Message: fmt.Sprintf("RRSIG for %s in %s has expired", rrtype, zone),
	}
}
