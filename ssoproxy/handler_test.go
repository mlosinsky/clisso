package ssoproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mlosinsky/clisso/ssoproxy/internal"
	"github.com/stretchr/testify/assert"
)

func TestOIDCLoginHandlerSuccessfulLogin(t *testing.T) {
	t.Parallel()
	context := NewContext(OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "client-id",
		ClientSecret:     "client-secret",
	})
	server := httptest.NewServer(OIDCLoginHandler(context))
	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	defer res.Body.Close()

	eventCounter := 0
	_ = internal.ConsumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == "auth-uri" && eventCounter == 0 {
				loginURI, err := url.Parse(data)
				assert.NoError(t, err)
				reqId := loginURI.Query().Get("state")
				assert.NotEmpty(t, reqId)
				// mock a redirect from IdP
				_ = context.onLoginSuccess(reqId, "mock-access-token", "mock-refresh-token", 600)
			} else if event == "oidc-tokens" && eventCounter == 1 {
				var tokensEvent tokensEvent
				err := json.Unmarshal([]byte(data), &tokensEvent)
				assert.NoError(t, err, "Access and refresh token could not be deserialized")
				assert.Equal(t, "mock-access-token", tokensEvent.AccessToken)
				assert.Equal(t, "mock-refresh-token", tokensEvent.RefreshToken)
				assert.Equal(t, 600, tokensEvent.Expiration)
			} else {
				t.Errorf("Received unexpected event type '%s' as %d. event", event, eventCounter)
			}
			eventCounter++
			return nil
		},
	)
	assert.Equal(t, 2, eventCounter)
	assert.Empty(t, context.requests)
}

func TestOIDCLoginHandlerLoginError(t *testing.T) {
	t.Parallel()
	context := NewContext(OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "client-id",
		ClientSecret:     "client-secret",
	})
	server := httptest.NewServer(OIDCLoginHandler(context))
	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	defer res.Body.Close()

	eventCounter := 0
	_ = internal.ConsumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == "auth-uri" && eventCounter == 0 {
				loginURI, err := url.Parse(data)
				assert.NoError(t, err)
				reqId := loginURI.Query().Get("state")
				assert.NotEmpty(t, reqId)
				// mock a redirect from IdP
				context.onLoginError(reqId, errors.New("mock-oidc-error"))
			} else if event == "error" && eventCounter == 1 {
				assert.NotEmpty(t, data)
				assert.Contains(t, data, "mock-oidc-error")
			} else {
				t.Errorf("Received unexpected event type '%s' as %d. event", event, eventCounter)
			}
			eventCounter++
			return nil
		},
	)
	assert.Equal(t, 2, eventCounter)
	assert.Empty(t, context.requests)
}

func TestOIDCLoginHandlerTimeout(t *testing.T) {
	t.Parallel()
	context := NewContext(OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "client-id",
		ClientSecret:     "client-secret",
	})
	context.LoginTimeout = 100 * time.Millisecond
	server := httptest.NewServer(OIDCLoginHandler(context))
	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	defer res.Body.Close()

	eventCounter := 0
	_ = internal.ConsumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == "auth-url" && eventCounter == 0 {
				loginURI, err := url.Parse(data)
				assert.NoError(t, err)
				reqId := loginURI.Query().Get("state")
				assert.NotEmpty(t, reqId)
				// wait for login to timeout
				time.Sleep(150 * time.Millisecond)
			} else if event == "error" && eventCounter == 1 {
				assert.NotEmpty(t, data)
			} else {
				t.Errorf("Received unexpected event type '%s' as %d. event", event, eventCounter)
			}
			eventCounter++
			return nil
		},
	)
	assert.Equal(t, 2, eventCounter)
	assert.Empty(t, context.requests)
}

func TestOIDCRedirectHandlerRedirectAfterSuccessfulLogin(t *testing.T) {
	t.Parallel()
	oidcConfig := OIDCConfig{
		BaseURI:          "http://localhost:8000/mock-idp",
		RedirectURI:      "http://localhost:8001/cli-oidc-redirect",
		AuthorizationURI: "http://localhost:8000/mock-idp/auth",
		ClientId:         "mock-client-id",
		ClientSecret:     "mock-client-secret",
	}
	mockOIDCServer := internal.CreateMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
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
	mockOIDCServer := internal.CreateMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
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
	mockOIDCServer := internal.CreateMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
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
	mockOIDCServer := internal.CreateMockOIDCServer("mock-auth-code", oidcConfig.ClientId, oidcConfig.ClientSecret, oidcConfig.RedirectURI)
	oidcConfig.BaseURI = mockOIDCServer.URL

	context := NewContext(oidcConfig)
	context.LoginTimeout = time.Millisecond * 100
	server := httptest.NewServer(OIDCRedirectHandler(context))
	go context.initiateLogin("11111111", func(loginResult *loginResult) {})

	time.Sleep(time.Millisecond * 150) // wait for login session to time out
	res, _ := http.Get(fmt.Sprint(server.URL, "?state=11111111&code=mock-auth-code"))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}
