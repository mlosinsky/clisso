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
	Expiration   int    `json:"expiration"`
}

type tokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
}

const reqIdLength = 8
const reqIdLogArg = "req-id"

const eventAuthURI = "auth-uri"
const eventLoggedIn = "logged-in"
const eventError = "error"

// Handles login process from an application. Sends text/event-stream response and
// writes Server-Sent Events to it during the login process.
// OIDCRedirectHandler must be used with this handler.
//
// Events can be of 3 types:
//
//	"auth-uri" // data = "https://some-sso.com/auth"
//	"logged-in" // data = `{"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}` as JSON
//	"error" // data = "Error description"
func OIDCLoginHandler(ctx *Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set proper SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		reqId, err := generateReqId()
		if err != nil {
			ctx.Logger.Error(fmt.Sprintf("Failed to generate request id: %v", err))
			sendSSEEvent(w, ctx, "Failed to generate random request id", eventError)
			return
		}

		authURI, err := url.Parse(ctx.config.AuthorizationURI)
		if err != nil {
			ctx.Logger.Warn(fmt.Sprintf("Invalid OIDC authorization URI: %s", ctx.config.AuthorizationURI))
			sendSSEEvent(w, ctx, "Invalid authorization URI", eventError)
			return
		}
		query := authURI.Query()
		query.Set("state", reqId)
		authURI.RawQuery = query.Encode()
		ctx.Logger.Info("Sending OIDC authorization URI to client", reqIdLogArg, reqId)
		sendSSEEvent(w, ctx, authURI.String(), eventAuthURI)

		// Wait for redirect from Identity Provider
		ctx.initiateLogin(reqId, func(loginResult *loginResult) {
			ctx.Logger.Info("Received login result from OIDC redirect handler", reqIdLogArg, reqId)
			if loginResult.err != nil {
				ctx.Logger.Warn(fmt.Sprintf("OIDC login failed: %v", err), reqIdLogArg, reqId)
				sendSSEEvent(w, ctx, fmt.Sprintf("OIDC login failed, reason: %v", loginResult.err), eventError)
				return
			}
			eventData, err := json.Marshal(tokensEvent{
				AccessToken:  loginResult.accessToken,
				RefreshToken: loginResult.refreshToken,
				Expiration:   loginResult.expiration,
			})
			if err != nil {
				ctx.Logger.Error(fmt.Sprintf("Could not marshal login result event to JSON: %v", err), reqIdLogArg, reqId)
				sendSSEEvent(w, ctx, "Failed to generate token event", eventError)
				return
			}
			ctx.Logger.Info("Sending successful login result to client", reqIdLogArg, reqId)
			sendSSEEvent(w, ctx, string(eventData), eventLoggedIn)
		})
	})
}

// Handles redirect from OIDC Identity Provider.
// Must serve on OIDC Redirect URI, uses OIDC authorization code flow.
func OIDCRedirectHandler(ctx *Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// uses a small middleware for error handling and redirecting
		reqId := r.URL.Query().Get("state")
		ctx.Logger.Info("Received OIDC login redirect", reqIdLogArg, reqId)
		statusCode, err := func(w http.ResponseWriter, r *http.Request) (int, error) {
			if r.Method != http.MethodGet {
				return http.StatusMethodNotAllowed, fmt.Errorf("HTTP method %s is not allowed", r.Method)
			} else if !r.URL.Query().Has("state") { // Request id has to be in state, because it was sent to IdP
				return http.StatusBadRequest, errors.New("OIDC URL query parameter 'state' was expected, but is missing")
			} else if !r.URL.Query().Has("code") {
				return http.StatusBadRequest, errors.New("OIDC URL query parameter 'code' was expected, but is missing")
			}
			reqId := r.URL.Query().Get("state")
			authorizationCode := r.URL.Query().Get("code")
			tokenRes, err := oidcGetTokens(authorizationCode, ctx.config)
			if err != nil {
				ctx.onLoginError(reqId, errors.New("failed to retrieve tokens from authorization code"))
				return http.StatusInternalServerError, errors.Join(errors.New("failed to retrieve tokens from authorization code"), err)
			}
			if err = ctx.onLoginSuccess(reqId, tokenRes.AccessToken, tokenRes.RefreshToken, tokenRes.ExpiresIn); err != nil {
				return http.StatusBadRequest, errors.New("received request id does not exist in context, user's login attempt probably timed out")
			}
			return http.StatusOK, nil
		}(w, r)

		if statusCode >= http.StatusBadRequest {
			if statusCode >= http.StatusInternalServerError {
				ctx.Logger.Error(fmt.Sprintf("OIDC redirect ended with error (status: %d): %v", statusCode, err), reqIdLogArg, reqId)
			} else {
				ctx.Logger.Warn(fmt.Sprintf("OIDC redirect ended with error (status: %d): %v", statusCode, err), reqIdLogArg, reqId)
			}
			if ctx.FailedRedirectURI != "" {
				http.Redirect(w, r, ctx.FailedRedirectURI, http.StatusPermanentRedirect)
			} else if statusCode >= http.StatusInternalServerError {
				http.Error(w, "An error was encountered while serving the request", statusCode)
			} else {
				http.Error(w, err.Error(), statusCode)
			}
		} else if statusCode == http.StatusOK {
			ctx.Logger.Info("Successfully finished handling OIDC login redirect", reqIdLogArg, reqId)
			if ctx.SuccessRedirectURI != "" {
				http.Redirect(w, r, ctx.SuccessRedirectURI, http.StatusPermanentRedirect)
			}
		}
	})
}

// Gets access and refresh tokens from OIDC provider.
func oidcGetTokens(authorizationCode string, config OIDCConfig) (*tokenResponse, error) {
	data := url.Values{}
	data.Set("code", authorizationCode)
	data.Set("client_id", config.ClientId)
	data.Set("client_secret", config.ClientSecret)
	data.Set("redirect_uri", config.RedirectURI)
	data.Set("grant_type", "authorization_code")
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/token", config.BaseURI), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	tokens := &tokenResponse{}
	if err := json.NewDecoder(res.Body).Decode(tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// Writes Server-Sent Event to response body and sends it to client.
func sendSSEEvent(w http.ResponseWriter, ctx *Context, data string, event string) {
	ctx.Logger.Debug(fmt.Sprintf("Sending SSE event '%s' with data '%s'", event, data))
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	w.(http.Flusher).Flush()
}

// Generates a random request id.
func generateReqId() (string, error) {
	randBytes := make([]byte, reqIdLength)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randBytes), nil
}
