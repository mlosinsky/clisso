package ssoproxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type tokensEvent struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

const reqIdLength = 8

const eventAuthURL = "auth-url"
const eventOIDCTokens = "oidc-tokens"
const eventError = "error"

// Handles login process from an application. Sends text/event-stream response and
// writes Server-Sent Events to it during the login process.
// OIDCRedirectHandler must be used with this handler.
//
// Events can be of 3 types: auth-url, oidc-tokens and error.
func OIDCLoginHandler(ctx *Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set proper SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		reqId, err := generateReqId()
		if err != nil {
			sendSSEEvent(w, ctx, "Failed to generate random request id", eventError)
			return
		}

		authUrl, err := url.Parse(ctx.config.AuthorizationURI)
		if err != nil {
			sendSSEEvent(w, ctx, "Invalid authorization URL", eventError)
			return
		}
		// ctx.onLoginInitiated(reqId)
		query := authUrl.Query()
		query.Set("state", reqId)
		authUrl.RawQuery = query.Encode()
		sendSSEEvent(w, ctx, authUrl.String(), eventAuthURL)

		// Wait for redirect from Identity Provider
		ctx.initiateLogin(reqId, func(access, refresh string, err error) {
			if err != nil {
				sendSSEEvent(w, ctx, fmt.Sprintf("OIDC login failed, reason: %s", err.Error()), eventError)
				return
			}
			eventData, err := json.Marshal(tokensEvent{AccessToken: access, RefreshToken: refresh})
			if err != nil {
				sendSSEEvent(w, ctx, "Failed to generate token event", eventError)
				return
			}
			ctx.Logger.Info("Login endpoint received OIDC tokens from IdP")
			sendSSEEvent(w, ctx, string(eventData), eventOIDCTokens)
		})
	})
}

// Handles redirect from Identity Provider.
// Must serve on OIDC Redirect URI, uses OIDC authorization code flow.
func OIDCRedirectHandler(ctx *Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// uses a small middleware for error handling and redirecting
		statusCode, err := func(w http.ResponseWriter, r *http.Request) (int, error) {
			if r.Method != http.MethodGet {
				return http.StatusMethodNotAllowed, fmt.Errorf("HTTP method %s is not allowed", r.Method)
			} else if !r.URL.Query().Has("state") { // Request id has to be in state, because it was sent to IdP
				return http.StatusBadRequest, errors.New("OIDC URL query parameter 'state' was expected, but is missing")
			} else if !r.URL.Query().Has("code") {
				return http.StatusBadRequest, errors.New("OIDC URL query parameter 'code' was expected, but is missing")
			}
			reqId := r.URL.Query().Get("state")
			ctx.Logger.Debug(fmt.Sprintf("Request id received in OIDC login redirect: %s", reqId))
			authorizationCode := r.URL.Query().Get("code")
			tokenResponse, err := oidcGetTokens(authorizationCode, ctx.config)
			if err != nil {
				ctx.onLoginError(reqId, errors.New("failed to retrieve tokens from authorization code"))
				return http.StatusInternalServerError, errors.New("failed to retrieve tokens from authorization code")
			}
			if err = ctx.onLoginSuccess(reqId, tokenResponse.AccessToken, tokenResponse.RefreshToken); err != nil {
				return http.StatusBadRequest, errors.New("received request id does not exist in context, user's login attemt probably timed out")
			}
			ctx.Logger.Info("Successfully finished handling OIDC login redirect")
			return http.StatusOK, nil
		}(w, r)

		if statusCode >= http.StatusInternalServerError {
			ctx.Logger.Error(err.Error())
		} else if statusCode != http.StatusOK {
			ctx.Logger.Warn(err.Error())
		}
		if statusCode >= http.StatusBadRequest && ctx.FailedRedirectURL == "" {
			http.Error(w, err.Error(), statusCode)
		} else if statusCode >= http.StatusBadRequest {
			http.Redirect(w, r, ctx.FailedRedirectURL, http.StatusPermanentRedirect)
		} else if ctx.SuccessRedirectURL != "" {
			http.Redirect(w, r, ctx.SuccessRedirectURL, http.StatusPermanentRedirect)
		}
	})
}

type tokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// Gets access and refresh tokens from OIDC provider
func oidcGetTokens(authorizationCode string, config OIDCConfig) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("code", authorizationCode)
	data.Set("client_id", config.ClientId)
	data.Set("client_secret", config.ClientSecret)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("grant_type", "authorization_code")
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/token", config.BaseURI), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	tokens := &tokenResponse{}
	if err := json.NewDecoder(res.Body).Decode(tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// Writes Server-Sent Event to response body and sends it to client
func sendSSEEvent(w http.ResponseWriter, ctx *Context, data string, event string) {
	ctx.Logger.Debug(fmt.Sprintf("Sending SSE event '%s' with data '%s'", event, data))
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	w.(http.Flusher).Flush()
}

// Generates a random request id
func generateReqId() (string, error) {
	randBytes := make([]byte, reqIdLength)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randBytes), nil
}
