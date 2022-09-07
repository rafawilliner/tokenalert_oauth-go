package oauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOauthConstants(t *testing.T) {
	assert.EqualValues(t, "X-Public", headerXPublic)
	assert.EqualValues(t, "X-Client-Id", headerXClientId)
	assert.EqualValues(t, "X-Caller-Id", headerXCallerId)
	assert.EqualValues(t, "access_token", paramAccessToken)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil))
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPublic(&request))

	request.Header.Add("X-Public", "true")
	assert.True(t, IsPublic(&request))
}

func TestGetCallerIdNilRequest(t *testing.T) {
	var request *http.Request
	ret := GetCallerId(request)
	assert.Equal(t, int64(0), ret)
}

func TestGetCallerInvalidCallerFormat(t *testing.T) {
	request, _ := http.NewRequest("GET", "http://example.com", nil)
	request.Header.Add("invalid", "fake-val")

	ret := GetCallerId(request)
	assert.Equal(t, int64(0), ret)
}

func TestGetCalleOK(t *testing.T) {
	request, _ := http.NewRequest("GET", "http://example.com", nil)
	request.Header.Add(headerXCallerId, "123")

	ret := GetCallerId(request)
	assert.Equal(t, int64(123), ret)
}