package ssoproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOIDCRedirectHandlerRedirectAfterSuccessfulLogin(t *testing.T) {
	t.Parallel()
	oidcConfig := OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "mock-client-id",
		ClientSecret:     "mock-client-secret",
	}
	mockOIDCServer := createMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
	oidcConfig.BaseURI = mockOIDCServer.URL

	context := NewContext(oidcConfig)
	context.SuccessRedirectURI = "http://localhost:8001/logged-in"
	server := httptest.NewServer(OIDCRedirectHandler(context))
	go context.initiateLogin("12345678", func(loginResult *loginResult) {})

	// don't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, _ := client.Get(fmt.Sprint(server.URL, "?state=12345678&code=mock-auth-code"))
	assert.Equal(t, http.StatusPermanentRedirect, res.StatusCode)
	assert.Equal(t, "http://localhost:8001/logged-in", res.Header.Get("Location"))
}

func TestOIDCRedirectHandlerRedirectAfterFailedLogin(t *testing.T) {
	t.Parallel()
	oidcConfig := OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "mock-client-id",
		ClientSecret:     "mock-client-secret",
	}
	mockOIDCServer := createMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
	oidcConfig.BaseURI = mockOIDCServer.URL

	context := NewContext(oidcConfig)
	context.FailedRedirectURI = "http://localhost:8001/logged-in"
	server := httptest.NewServer(OIDCRedirectHandler(context))
	go context.initiateLogin("12345678", func(loginResult *loginResult) {})

	// don't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// use wrong auth code to fail the request
	res, _ := client.Get(fmt.Sprint(server.URL, "?state=12345678&code=wrong-auth-code"))
	assert.Equal(t, http.StatusPermanentRedirect, res.StatusCode)
	assert.Equal(t, "http://localhost:8001/logged-in", res.Header.Get("Location"))
}

func TestOIDCRedirectHandlerWontRedirectByDefault(t *testing.T) {
	t.Parallel()
	oidcConfig := OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "mock-client-id",
		ClientSecret:     "mock-client-secret",
	}
	mockOIDCServer := createMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
	oidcConfig.BaseURI = mockOIDCServer.URL

	context := NewContext(oidcConfig)
	server := httptest.NewServer(OIDCRedirectHandler(context))
	go context.initiateLogin("12345678", func(loginResult *loginResult) {})

	// don't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// use wrong auth code to fail the request
	res, _ := client.Get(fmt.Sprint(server.URL, "?state=12345678&code=mock-auth-code"))
	assert.NotEqual(t, http.StatusPermanentRedirect, res.StatusCode)
	assert.Empty(t, res.Header.Get("Location"))
}

func TestOIDCRedirectHandlerReturnsErrorOnExpiredRequestId(t *testing.T) {
	t.Parallel()
	oidcConfig := OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "mock-client-id",
		ClientSecret:     "mock-client-secret",
	}
	mockOIDCServer := createMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
	oidcConfig.BaseURI = mockOIDCServer.URL

	context := NewContext(oidcConfig)
	context.LoginTimeout = time.Millisecond * 100
	server := httptest.NewServer(OIDCRedirectHandler(context))
	go context.initiateLogin("11111111", func(loginResult *loginResult) {})

	time.Sleep(time.Millisecond * 150) // wait for login session to time out
	res, _ := http.Get(fmt.Sprint(server.URL, "?state=11111111&code=mock-auth-code"))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func createMockOIDCServer(expectedAuthCode, expectedClientId, expectedClientSecret, expectedRedirectURI string) httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, fmt.Sprintf("Invalid grant_type: %s", r.Form.Get("grant_type")), http.StatusBadRequest)
		} else if r.Form.Get("code") != expectedAuthCode {
			http.Error(w, fmt.Sprintf("Invalid code %s, expected %s", r.Form.Get("code"), expectedAuthCode), http.StatusBadRequest)
		} else if r.Form.Get("client_id") != expectedClientId {
			http.Error(w, fmt.Sprintf("Invalid client_id %s, expected %s", r.Form.Get("client_id"), expectedAuthCode), http.StatusBadRequest)
		} else if r.Form.Get("client_secret") != expectedClientSecret {
			http.Error(w, fmt.Sprintf("Invalid client_secret %s, expected %s", r.Form.Get("client_secret"), expectedClientSecret), http.StatusBadRequest)
		} else if r.Form.Get("redirect_uri") != expectedRedirectURI {
			http.Error(w, fmt.Sprintf("Invalid redirect_uri %s, expected %s", r.Form.Get("redirect_uri"), expectedRedirectURI), http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(`{"access_token":"mock-access-token","refresh_token":"mock-refresh-token"}`))
	})
	return *httptest.NewServer(mux)
}
