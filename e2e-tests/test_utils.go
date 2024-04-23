package e2e_tests

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Needs to be in a separate package to prevent import cycle
type ProxyConfig struct {
	BaseURI          string
	AuthorizationURI string
	DeviceAuthURI    string
	TokenURI         string
	LogoutURI        string
	ClientId         string
	ClientSecret     string
	ProxyLoginURI    string
}

type ContainerStartResult struct {
	Container testcontainers.Container
	Err       error
}

// Configures and starts proxy on host network
func StartSSOProxy(port int, config ProxyConfig) ContainerStartResult {
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			// Context path must be relative tested package
			Context: "../../",
			// Dockerfile path must be relative to Context
			Dockerfile: "Dockerfile.proxy",
			KeepImage:  false, // do not cache image, proxy can change between CI runs
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.NetworkMode = "host"
			hc.AutoRemove = true
		},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		},
		Env: map[string]string{
			"HTTP_PORT":              strconv.Itoa(port),
			"OIDC_BASE_URI":          config.BaseURI,
			"OIDC_REDIRECT_URI":      fmt.Sprintf("http://localhost:%d/cli-logged-in", port),
			"OIDC_AUTHORIZATION_URI": config.AuthorizationURI,
			"OIDC_CLIENT_ID":         config.ClientId,
			"OIDC_CLIENT_SECRET":     config.ClientSecret,
		},
		ExposedPorts: []string{fmt.Sprintf("%d/tcp", port)},
		// sometimes it takes more than 1 minute (default) to build and start proxy
		WaitingFor: wait.ForLog("HTTP server started").WithStartupTimeout(2 * time.Minute),
	}
	proxy, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return ContainerStartResult{Container: proxy, Err: err}
}

func OIDCLogout(proxyConfig ProxyConfig, refreshToken string) {
	http.PostForm(proxyConfig.LogoutURI, url.Values{
		"refresh_token": {refreshToken},
		"client_id":     {proxyConfig.ClientId},
	})
}

// utility function to get port of container or panic on error
func GetPortOrPanic(container testcontainers.Container, port nat.Port) int {
	mappedPort, err := container.MappedPort(context.Background(), port)
	if err != nil {
		container.GetContainerID()
		panic(fmt.Sprintf("Port %v not found on container %s: %v", port, container.GetContainerID(), err))
	}
	exposedPort, err := strconv.Atoi(mappedPort.Port())
	if err != nil {
		panic(fmt.Sprintf("Port %v not found on container %s: %v", port, container.GetContainerID(), err))
	}
	return exposedPort
}
