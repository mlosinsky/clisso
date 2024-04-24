package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/mlosinsky/clisso/ssoproxy"
)

func startHTTPServer(port int) {
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		slog.Error(fmt.Sprintf("Failed to start HTTP server on port %d: %s", port, err))
	}
}

func main() {
	context := ssoproxy.NewContext(ssoproxy.OIDCConfig{
		BaseURI:          os.Getenv("OIDC_BASE_URI"),
		RedirectURI:      os.Getenv("OIDC_REDIRECT_URI"),
		AuthorizationURI: os.Getenv("OIDC_AUTHORIZATION_URI"),
		ClientId:         os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:     os.Getenv("OIDC_CLIENT_SECRET"),
	})
	context.Logger = slog.Default()
	http.Handle("/cli-login", ssoproxy.OIDCLoginHandler(context))
	http.Handle("/cli-logged-in", ssoproxy.OIDCRedirectHandler(context))

	port, err := strconv.Atoi(os.Getenv("HTTP_PORT"))
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to start HTTP server: invalid env HTTP_PORT '%v'", os.Getenv("HTTP_PORT")))
		os.Exit(1)
	}
	httpServerChan := make(chan bool)
	go startHTTPServer(port)
	slog.Info("HTTP server started")
	<-httpServerChan
	slog.Info("HTTP server stopped")
}
