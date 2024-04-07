package ssoclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginWithOIDCProxySuccessWithoutWaiting(t *testing.T) {
	t.Parallel()
	mockProxy := createMockProxy(true, time.Millisecond*5)
	result, err := LoginWithSSOProxy(fmt.Sprintf("%s/cli-login", mockProxy.URL), func(loginURI string) {})
	assert.NoError(t, err)
	assert.Equal(t, "mock-access-token", result.AccessToken)
	assert.Equal(t, "mock-refresh-token", result.RefreshToken)
	assert.Equal(t, 3600, result.Expiration)
}

func TestLoginWithOIDCProxySuccessWithWaiting(t *testing.T) {
	t.Parallel()
	mockProxy := createMockProxy(true, time.Second*1)
	result, err := LoginWithSSOProxy(fmt.Sprintf("%s/cli-login", mockProxy.URL), func(loginURI string) {})
	assert.NoError(t, err)
	assert.Equal(t, "mock-access-token", result.AccessToken)
	assert.Equal(t, "mock-refresh-token", result.RefreshToken)
	assert.Equal(t, 3600, result.Expiration)
}

func TestLoginWithOIDCProxyFail(t *testing.T) {
	t.Parallel()
	mockProxy := createMockProxy(false, time.Millisecond*5)
	_, err := LoginWithSSOProxy(fmt.Sprintf("%s/cli-login", mockProxy.URL), func(loginURI string) {})
	assert.Error(t, err)
}

func createMockProxy(loginSuccess bool, loginAfter time.Duration) httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/cli-login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventAuthURI, "http://sso.mock")
		w.(http.Flusher).Flush()
		time.Sleep(loginAfter)
		if loginSuccess {
			tokens, _ := json.Marshal(proxyTokensEvent{
				AccessToken:  "mock-access-token",
				RefreshToken: "mock-refresh-token",
				Expiration:   3600,
			})
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventLoggedIn, tokens)
		} else {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventError, "mock sso proxy error")
		}
		w.(http.Flusher).Flush()
	})
	return *httptest.NewServer(mux)
}
