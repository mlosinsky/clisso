package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/docker/docker/api/types/container"
	"github.com/mlosinsky/clisso/e2e_tests"
	"github.com/mlosinsky/clisso/ssoclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const vaultRootToken = "root" // used for configuring Vault JWT auth
var vaultPort int             // needed for tests accessing Vault API

var proxyConfig e2e_tests.ProxyConfig

func startKeycloak(network *testcontainers.DockerNetwork) e2e_tests.ContainerStartResult {
	req := testcontainers.ContainerRequest{
		Image: "quay.io/keycloak/keycloak:23.0",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.AutoRemove = true
		},
		Networks:       []string{network.Name},
		NetworkAliases: map[string][]string{network.Name: {"keycloak"}},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./keycloak-realm-export.json",
				ContainerFilePath: "/opt/keycloak/data/import/realm-export.json",
				FileMode:          0o666,
			},
		},
		ExposedPorts: []string{"8080/tcp"},
		Cmd:          []string{"start-dev", "--import-realm"},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		},
		WaitingFor: wait.ForLog("Listening on").WithStartupTimeout(2 * time.Minute),
	}
	keycloak, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return e2e_tests.ContainerStartResult{Container: keycloak, Err: err}
}

func startVault(network *testcontainers.DockerNetwork) e2e_tests.ContainerStartResult {
	req := testcontainers.ContainerRequest{
		Image: "hashicorp/vault:1.15",
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapAdd = []string{"IPC_LOCK"}
			hc.AutoRemove = true
		},
		// must be on the same network for Vault to access OIDC discovery URL
		Networks:     []string{network.Name},
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_ADDR":     "http://0.0.0.0:8200",
			"VAULT_API_ADDR": "http://0.0.0.0:8200",
		},
		Entrypoint: []string{"vault", "server", "-dev", "-dev-listen-address=0.0.0.0:8200", fmt.Sprintf("-dev-root-token-id=%s", vaultRootToken)},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		},
		WaitingFor: wait.ForHTTP("/v1/sys/health").WithPort("8200"),
	}
	vault, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	return e2e_tests.ContainerStartResult{Container: vault, Err: err}
}

func makeVaultHTTPPostRequest(uri string, body string) error {
	req, err := http.NewRequest("POST", uri, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Vault-Token", "root")
	_, err = http.DefaultClient.Do(req)
	return err
}

func configureVaultJWTAuth(vaultPort int) error {
	jwtEnableErr := makeVaultHTTPPostRequest(
		fmt.Sprintf("http://localhost:%d/v1/sys/auth/jwt", vaultPort),
		`{"type": "jwt", "description": "Login with JWT from Keycloak"}`,
	)
	if jwtEnableErr != nil {
		return jwtEnableErr
	}
	jwtConfigErr := makeVaultHTTPPostRequest(
		fmt.Sprintf("http://localhost:%d/v1/auth/jwt/config", vaultPort),
		`{"oidc_discovery_url": "http://keycloak:8080/realms/test","default_role": "demo"}`,
	)
	if jwtConfigErr != nil {
		return jwtConfigErr
	}
	// bound_subject must be the same as user id from Keycloak realm import
	// allowed_redirect_uris must contain redirect uri configured for Keycloak
	roleCreateErr := makeVaultHTTPPostRequest(
		fmt.Sprintf("http://localhost:%d/v1/auth/jwt/role/test", vaultPort),
		`{
			"role_type": "jwt",
			"ttl": "1h",
			"token_policies": "webapps",
			"bound_subject": "5fa31cca-ea5a-49f8-b828-3db5f6ae71f9",
			"allowed_redirect_uris": "http://localhost:8000/cli-logged-in",
			"user_claim": "vault_user"
		}`,
	)
	return roleCreateErr
}

func setup() (teardowns []func() error, err error) {
	network, err := network.New(context.Background(),
		network.WithCheckDuplicate(),
		network.WithAttachable(),
	)
	if err != nil {
		return teardowns, err
	}
	teardowns = append(teardowns, func() error { return network.Remove(context.Background()) })

	keycloakChan := make(chan e2e_tests.ContainerStartResult)
	vaultChan := make(chan e2e_tests.ContainerStartResult)

	go func() { keycloakChan <- startKeycloak(network) }()
	go func() { vaultChan <- startVault(network) }()
	keycloak := <-keycloakChan
	vault := <-vaultChan
	if keycloak.Err == nil {
		teardowns = append(teardowns, func() error { return keycloak.Container.Terminate(context.Background()) })
	}
	if vault.Err == nil {
		teardowns = append(teardowns, func() error { return vault.Container.Terminate(context.Background()) })
	}
	if keycloak.Err != nil {
		return teardowns, errors.New("Keycloak error: " + keycloak.Err.Error())
	}
	if vault.Err != nil {
		return teardowns, errors.New("Vault error: " + vault.Err.Error())
	}

	vaultPort = e2e_tests.GetPortOrPanic(vault.Container, "8200")
	keycloakPort := e2e_tests.GetPortOrPanic(keycloak.Container, "8080")
	err = configureVaultJWTAuth(vaultPort)
	if err != nil {
		return teardowns, errors.New("Vault JWT config error: " + err.Error())
	}
	proxyConfig = e2e_tests.ProxyConfig{
		BaseURI:          fmt.Sprintf("http://localhost:%d/realms/test/protocol/openid-connect", keycloakPort),
		AuthorizationURI: fmt.Sprintf("http://localhost:%d/realms/test/protocol/openid-connect/auth?response_type=code&scope=openid&client_id=test&redirect_uri=http://localhost:8000/cli-logged-in", keycloakPort),
		LogoutURI:        fmt.Sprintf("http://localhost:%d/realms/test/protocol/openid-connect/logout", keycloakPort),
		ClientId:         "test",
		ClientSecret:     "YscDX1J39s7PDBbpBJWsGyOLdl8TJEUK",
		DeviceAuthURI:    fmt.Sprintf("http://localhost:%d/realms/test/protocol/openid-connect/auth/device", keycloakPort),
		TokenURI:         fmt.Sprintf("http://localhost:%d/realms/test/protocol/openid-connect/token", keycloakPort),
		ProxyLoginURI:    "http://localhost:8000/cli-login",
	}
	proxy := e2e_tests.StartSSOProxy(8000, proxyConfig)
	if proxy.Err == nil {
		teardowns = append(teardowns, func() error { return proxy.Container.Terminate(context.Background()) })
	}
	return teardowns, err
}

func TestMain(m *testing.M) {
	teardowns, err := setup()
	if err != nil {
		fmt.Println("Failed to setup Keycloak E2E tests:", err)
		os.Exit(1)
	}
	code := m.Run()
	errs := []string{}
	for _, teardown := range teardowns {
		if err := teardown(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) != 0 {
		fmt.Println("Failed to teardown Keycloak E2E tests:")
		fmt.Println(strings.Join(errs, "\n"))
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
				chromedp.WaitVisible("input[name='username']"),
				chromedp.WaitVisible("input[name='password']"),
				chromedp.SendKeys("input[name='username']", "mlosinsky"),
				chromedp.SendKeys("input[name='password']", "mlosinsky"),
				chromedp.Submit("input[name='username']"),
				chromedp.WaitReady("html"),
			)
			require.NoError(t, err)
		},
	)
	t.Cleanup(func() { e2e_tests.OIDCLogout(proxyConfig, loginResult.RefreshToken) })
	assert.NoError(t, err)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.RefreshToken)
	assert.NotEmpty(t, loginResult.Expiration)
}

type VaultLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

func TestSSOLoginToVault(t *testing.T) {
	loginResult, err := ssoclient.LoginWithSSOProxy(
		proxyConfig.ProxyLoginURI,
		func(loginURI string) {
			ctx, cancel := chromedp.NewContext(context.Background())
			defer cancel()
			err := chromedp.Run(ctx,
				chromedp.Navigate(loginURI),
				chromedp.WaitVisible("input[name='username']"),
				chromedp.WaitVisible("input[name='password']"),
				chromedp.SendKeys("input[name='username']", "mlosinsky"),
				chromedp.SendKeys("input[name='password']", "mlosinsky"),
				chromedp.Submit("input[name='username']"),
				chromedp.WaitReady("html"),
			)
			require.NoError(t, err)
		},
	)
	t.Cleanup(func() { e2e_tests.OIDCLogout(proxyConfig, loginResult.RefreshToken) })
	require.NoError(t, err)

	// login to Vault from compose, JWT auth method was created by vault-init container
	res, err := http.Post(
		fmt.Sprintf("http://localhost:%d/v1/auth/jwt/login", vaultPort),
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"jwt":"%s","role":"test"}`, loginResult.AccessToken)),
	)
	require.NoError(t, err)
	defer res.Body.Close()
	rawBody, _ := io.ReadAll(res.Body)
	var body VaultLoginResponse
	require.NoError(t, json.Unmarshal(rawBody, &body))
	assert.NotEmpty(t, body.Auth.ClientToken)
}

func TestSuccessfulDeviceLogin(t *testing.T) {
	loginResult, err := ssoclient.LoginWithDeviceAuth(
		ssoclient.DeviceAuthConfig{
			DeviceAuthURI: proxyConfig.DeviceAuthURI,
			TokenURI:      proxyConfig.TokenURI,
			ClientId:      proxyConfig.ClientId,
		},
		func(verificationURI, userCode string) {
			ctx, cancel := chromedp.NewContext(context.Background())
			defer cancel()
			err := chromedp.Run(ctx,
				chromedp.Navigate(verificationURI),
				chromedp.WaitVisible("input[name='device_user_code']"),
				chromedp.SendKeys("input[name='device_user_code']", userCode),
				chromedp.Click("input[type='submit']"),
				chromedp.WaitVisible("input[name='username']"),
				chromedp.WaitVisible("input[name='password']"),
				chromedp.SendKeys("input[name='username']", "mlosinsky"),
				chromedp.SendKeys("input[name='password']", "mlosinsky"),
				chromedp.Click("input[type='submit']"),
				chromedp.WaitVisible("input[name='accept']"),
				chromedp.Click("input[name='accept']"),
				chromedp.WaitReady("html"),
			)
			require.NoError(t, err)
		},
	)

	t.Cleanup(func() { e2e_tests.OIDCLogout(proxyConfig, loginResult.RefreshToken) })
	assert.NoError(t, err)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.RefreshToken)
	assert.NotEmpty(t, loginResult.Expiration)
}
