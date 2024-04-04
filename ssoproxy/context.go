package ssoproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

type OIDCConfig struct {
	BaseURI          string
	RedirectURI      string
	AuthorizationURI string
	ClientId         string
	ClientSecret     string
}

type Context struct {
	config        OIDCConfig
	requests      map[string]chan *loginResult
	requestsMutex *sync.RWMutex
	// logger for HTTP handlers, does not log any messages by default
	Logger *slog.Logger
	// if set users will be redirected to it after login to IdP if the redirect processing was successful, won't redirect by default
	SuccessRedirectURI string
	// if set users will be redirected to it after login to IdP if the redirect processing failed, won't redirect by default
	FailedRedirectURI string
	// time for user to login to IdP after login was initiated, default 5 minutes
	LoginTimeout time.Duration
}

type loginResult struct {
	accessToken  string
	refreshToken string
	expiration   int
	err          error
}

func NewContext(oidcConfig OIDCConfig) *Context {
	return &Context{
		oidcConfig,
		make(map[string]chan *loginResult),
		&sync.RWMutex{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"",
		"",
		time.Minute * 5,
	}
}

func (ctx *Context) initiateLogin(reqId string, handler func(*loginResult)) {
	ctx.requestsMutex.Lock()
	ctx.requests[reqId] = make(chan *loginResult)
	ctx.requestsMutex.Unlock()
	timeoutCtx, cancel := context.WithTimeout(context.Background(), ctx.LoginTimeout)
	defer cancel()
	select {
	case loginResult := <-ctx.requests[reqId]:
		handler(loginResult)
	case <-timeoutCtx.Done():
		ctx.Logger.Warn("User's login session timed out")
		handler(&loginResult{err: errors.New("user's login session timed out")})
	}
	delete(ctx.requests, reqId)
}

// Writes tokens to session of request id, if there is no such session returns error
func (ctx *Context) onLoginSuccess(reqId, accessToken, refreshToken string, expiration int) error {
	if _, contains := ctx.requests[reqId]; !contains {
		return errors.New("user's session id does not exist in OIDC context")
	}
	ctx.requestsMutex.Lock()
	ctx.requests[reqId] <- &loginResult{
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiration:   expiration,
	}
	ctx.requestsMutex.Unlock()
	return nil
}

// Writes given error to session of request id, if there is no such session does nothing
func (ctx *Context) onLoginError(reqId string, err error) {
	if _, contains := ctx.requests[reqId]; !contains {
		return
	}
	ctx.requestsMutex.Lock()
	ctx.requests[reqId] <- &loginResult{
		err: err,
	}
	ctx.requestsMutex.Unlock()
}
