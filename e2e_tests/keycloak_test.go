package e2e_tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/mlosinsky/clisso/ssoclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TODO: run containers in beforeall and run multiple tests on them (in parallel)
// TODO: check/fix containers not removed
func TestSuccessfulLogin(t *testing.T) {
	compose, err := tc.NewDockerCompose("docker-compose.yaml")
	require.NoError(t, err, "NewDockerComposeAPI()")
	t.Cleanup(func() {
		require.NoError(t, compose.Down(context.Background(), tc.RemoveOrphans(true), tc.RemoveImagesLocal), "compose.Down()")
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	err = compose.
		WaitForService("keycloak", wait.ForLog(`.*Listening on.*`).AsRegexp().WithStartupTimeout(60*time.Second)).
		Up(ctx, tc.Wait(true))

	require.NoError(t, err, "compose.Up()")

	loginResult, err := ssoclient.LoginWithOIDCProxy(
		"http://localhost:8000/cli-login",
		func(loginURL string) {
			_, err := http.Get("http://localhost:8080/realms/test/protocol/openid-connect/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcli-logged-in&response_type=code&scope=openid&state=fc57191d9f160ec2")
			if err != nil {
				println(err.Error())
			}
			ctx, cancel := chromedp.NewContext(context.Background())
			defer cancel()
			err = chromedp.Run(ctx,
				chromedp.Navigate(loginURL),
				chromedp.WaitVisible("input[name='username']"),
				chromedp.WaitVisible("input[name='password']"),
				chromedp.SendKeys("input[name='username']", "mlosinsky"),
				chromedp.SendKeys("input[name='password']", "mlosinsky"),
				chromedp.Submit("input[name='username']"),
				chromedp.WaitReady("html"),
			)
			assert.NoError(t, err)
		},
	)
	assert.NoError(t, err)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.NotEmpty(t, loginResult.RefreshToken)
	assert.NotEmpty(t, loginResult.Expiration)
}

func TestChromedp(t *testing.T) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	var text string
	err := chromedp.Run(ctx,
		chromedp.Navigate("https://seznam.cz"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			fmt.Println("Navigated to loginURL ************")
			return nil
		}),
		chromedp.Text("a.article__title.link.link--show-visited", &text),
	)
	assert.Equal(t, "Naučte se poznávat padělané peníze a šejdíři vás nedostanou", text)
	assert.NoError(t, err)
}

func TestChromedpKeycloakAccess(t *testing.T) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// fmt.Println("http://localhost:8080/realms/test/protocol/openid-connect/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcli-logged-in&response_type=code&scope=openid&state=206f34dbcd35a048")
			return nil
		}),
		chromedp.Navigate("http://localhost:8080/realms/test/protocol/openid-connect/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcli-logged-in&response_type=code&scope=openid&state=206f34dbcd35a048"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			fmt.Println("Navigated to loginURL ************")
			return nil
		}),
		chromedp.WaitVisible("input[name='username']"),
		chromedp.WaitVisible("input[name='password']"),
		chromedp.SendKeys("input[name='username']", "mlosinsky"),
		chromedp.SendKeys("input[name='password']", "mlosinsky"),
		chromedp.Submit("input[name='username']"),
	)
	assert.NoError(t, err)
}
