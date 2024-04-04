package ssoclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginWithDeviceAuthWithoutPollingSuccess(t *testing.T) {
	t.Parallel()
	mockOAuthServer := createMockOAuthServer("mock-client-id", 1, 1)
	loginResult, err := LoginWithDeviceAuth(
		fmt.Sprintf("%s/auth/device", mockOAuthServer.URL),
		fmt.Sprintf("%s/token", mockOAuthServer.URL),
		"mock-client-id",
		func(verificationURI, userCode string) {
			_, err := http.Get(fmt.Sprintf("%s?user-code=mock-user-code", verificationURI))
			require.NoError(t, err)
		})
	assert.Equal(t, "mock-access-token", loginResult.AccessToken)
	assert.Equal(t, "mock-refresh-token", loginResult.RefreshToken)
	assert.NoError(t, err)
}

func TestLoginWithDeviceAuthWithPollingSuccess(t *testing.T) {
	t.Parallel()
	// client needs to poll 3 times after user login
	mockOAuthServer := createMockOAuthServer("mock-client-id", 1, 3)
	loginResult, err := LoginWithDeviceAuth(
		fmt.Sprintf("%s/auth/device", mockOAuthServer.URL),
		fmt.Sprintf("%s/token", mockOAuthServer.URL),
		"mock-client-id",
		func(verificationURI, userCode string) {
			_, err := http.Get(fmt.Sprintf("%s?user-code=mock-user-code", verificationURI))
			require.NoError(t, err)
		})
	assert.Equal(t, "mock-access-token", loginResult.AccessToken)
	assert.Equal(t, "mock-refresh-token", loginResult.RefreshToken)
	assert.NoError(t, err)
}

func createMockOAuthServer(expectedClientId string, pollInterval, neededPollCount int) httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid HTTP method", http.StatusMethodNotAllowed)
		} else if r.Form.Get("client_id") != expectedClientId {
			http.Error(w, fmt.Sprintf("Invalid client_id %s, expected %s", r.Form.Get("client_id"), expectedClientId), http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"device_code": "mock-device-code",
			"user_code": "mock-user-code",
			"verification_uri": "%[1]s",
			"verification_uri_complete": "%[1]s?user-code=mock-user-code",
			"expires_in": 600,
			"interval": %[2]d
		}`, fmt.Sprintf("http://%s/mock-auth", r.Host), pollInterval)))
	})

	// using atomic for possible concurrency issues - accessed by /mock-auth and /token
	loggedIn := atomic.Bool{}
	loggedIn.Store(false)
	mux.HandleFunc("/mock-auth", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user-code") != "mock-user-code" {
			http.Error(w, fmt.Sprintf("Invalid user-code %s, expected mock-user-code", r.URL.Query().Get("user-code")), http.StatusBadRequest)
		} else {
			loggedIn.Store(true)
		}
	})

	currPollCount := 0
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid HTTP method", http.StatusMethodNotAllowed)
		} else if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			http.Error(w, fmt.Sprintf("Invalid grant_type: %s", r.Form.Get("grant_type")), http.StatusBadRequest)
		} else if r.Form.Get("device_code") != "mock-device-code" {
			http.Error(w, fmt.Sprintf("Invalid code %s, expected mock-device-code", r.Form.Get("code")), http.StatusBadRequest)
		} else if r.Form.Get("client_id") != expectedClientId {
			http.Error(w, fmt.Sprintf("Invalid client_id %s, expected %s", r.Form.Get("client_id"), expectedClientId), http.StatusBadRequest)
		}
		currPollCount++
		if currPollCount >= neededPollCount && loggedIn.Load() {
			_, _ = w.Write([]byte(`{
				"access_token":"mock-access-token",
				"refresh_token":"mock-refresh-token",
				"expires_in": 3600
			}`))
		} else {
			http.Error(w, "", http.StatusBadRequest)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"%s"}`, authorizationPendingError)))
		}
	})
	return *httptest.NewServer(mux)
}
