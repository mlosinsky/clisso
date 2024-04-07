package ssoproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
	_ = consumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == eventAuthURI && eventCounter == 0 {
				loginURI, err := url.Parse(data)
				assert.NoError(t, err)
				reqId := loginURI.Query().Get("state")
				assert.NotEmpty(t, reqId)
				// mock a redirect from IdP
				_ = context.onLoginSuccess(reqId, "mock-access-token", "mock-refresh-token", 600)
			} else if event == eventLoggedIn && eventCounter == 1 {
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
	_ = consumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == eventAuthURI && eventCounter == 0 {
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
	_ = consumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == eventAuthURI && eventCounter == 0 {
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

func consumeSSEFromHTTPEventStream(
	httpBody io.ReadCloser,
	onEventReceived func(event, data string) error,
) error {
	scanner := bufio.NewScanner(httpBody)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		twoLineEnds := bytes.Index(data, []byte("\n\n"))
		if twoLineEnds >= 0 {
			return twoLineEnds + 2, data[0:twoLineEnds], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for {
		if scanner.Scan() {
			rawEvent := scanner.Text()
			event, data, err := parseSSEEvent(rawEvent)
			if err != nil {
				return errors.Join(errors.New("received invalid login event from proxy"), err)
			}
			if err = onEventReceived(event, data); err != nil {
				return errors.Join(errors.New("an error occurred during consuming a login event"), err)
			}
		} else {
			if err := scanner.Err(); err != nil {
				return errors.Join(errors.New("an error occurred while reading login events"), err)
			} else {
				return nil
			}
		}
	}
}

func parseSSEEvent(rawEvent string) (event, data string, err error) {
	parts := strings.Split(rawEvent, "\n")
	if len(parts) != 2 {
		return "", "", errors.New("event does not contain one or both fields 'event' and 'data' or has more fields")
	}
	event, valid := strings.CutPrefix(parts[0], "event: ")
	if !valid {
		return "", "", errors.New("SSE event field 'event' must start with 'event: '")
	}
	data, valid = strings.CutPrefix(parts[1], "data: ")
	if !valid {
		return "", "", errors.New("SSE event field 'data' must start with 'data: '")
	}
	return event, data, nil
}
