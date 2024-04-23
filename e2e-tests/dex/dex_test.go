package dex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/docker/docker/api/types/container"
	"github.com/mlosinsky/clisso/e2e_tests"
	"github.com/mlosinsky/clisso/ssoclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var proxyConfig e2e_tests.ProxyConfig

func startDex() e2e_tests.ContainerStartResult {
	req := testcontainers.ContainerRequest{
		Image: "ghcr.io/dexidp/dex:v2.39.1",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.AutoRemove = true
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./dex-config.yaml",
				ContainerFilePath: "/tmp/dex-config.yaml",
				FileMode:          0o666,
			},
		},
		ExposedPorts: []string{"5556/tcp"},
		Cmd:          []string{"dex", "serve", "/tmp/dex-config.yaml"},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		},
		WaitingFor: wait.ForLog("listening (http) on").WithStartupTimeout(30 * time.Second),
	}
	dex, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return e2e_tests.ContainerStartResult{Container: dex, Err: err}
}

func setup() (teardown func() error, err error) {
	dex := startDex()
	if dex.Err != nil {
		return nil, err
	}
	dexPort := e2e_tests.GetPortOrPanic(dex.Container, "5556")
	// dex port is chosen randomly by testcontainers, proxy configuration must be set afterwards
	proxyConfig = e2e_tests.ProxyConfig{
		BaseURI:          fmt.Sprintf("http://localhost:%d", dexPort),
		AuthorizationURI: fmt.Sprintf("http://localhost:%d/auth?response_type=code&scope=openid&client_id=sso-proxy&redirect_uri=http://localhost:8001/cli-logged-in", dexPort),
		LogoutURI:        fmt.Sprintf("http://localhost:%d/logout", dexPort),
		ClientId:         "sso-proxy",
		ClientSecret:     "safoaijewgnbioevnasdf",
		DeviceAuthURI:    fmt.Sprintf("http://localhost:%d/device/code", dexPort),
		TokenURI:         fmt.Sprintf("http://localhost:%d/token", dexPort),
		ProxyLoginURI:    "http://localhost:8001/cli-login",
	}
	proxy := e2e_tests.StartSSOProxy(8001, proxyConfig)
	if proxy.Err != nil {
		errDex := dex.Container.Terminate(context.Background())
		return nil, errors.Join(proxy.Err, errDex)
	}
	return func() error {
		errDex := dex.Container.Terminate(context.Background())
		errProxy := proxy.Container.Terminate(context.Background())
		return errors.Join(errDex, errProxy)
	}, nil
}

func TestMain(m *testing.M) {
	teardown, err := setup()
	if err != nil {
		fmt.Println("Failed to setup Dex E2E tests:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err := teardown(); err != nil {
		fmt.Println("Failed to teardown Dex E2E tests:", err)
	}
	os.Exit(code)
}

func TestSuccessfulProxyLogin(t *testing.T) {
	loginResult, err := ssoclient.LoginWithSSOProxy(
		proxyConfig.ProxyLoginURI,
		func(loginURI string) {
			ctx, cancel := chromedp.NewContext(context.Background())
			defer cancel()
			err := chromedp.Run(ctx,
				chromedp.Navigate(loginURI),
				chromedp.WaitVisible("input[name='login']"),
				chromedp.WaitVisible("input[name='password']"),
				chromedp.SendKeys("input[name='login']", "mlosinsky@test.com"),
				chromedp.SendKeys("input[name='password']", "password"),
				chromedp.Click("button[type='submit']"),
				chromedp.WaitReady("html"),
				chromedp.Click("button.theme-btn--success[type='submit']"),
				chromedp.WaitReady("html"),
			)
			require.NoError(t, err)
		},
	)
	t.Cleanup(func() { e2e_tests.OIDCLogout(proxyConfig, loginResult.RefreshToken) })
	assert.NoError(t, err)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.Expiration)
}
