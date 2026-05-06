package dnssec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_checkExponent(t *testing.T) {
	// Test with invalid base64
	result := checkExponent("!!!invalid!!!")
	assert.True(t, result) // Returns true on error

	// Test with too short key
	result = checkExponent("AQAB") // Very short
	assert.True(t, result)
}
