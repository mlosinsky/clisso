package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/mlosinsky/clisso/ssoclient"
)

type ctxKey string

const accessTokenKey ctxKey = "access_token"

func vaultAuth(loginContext context.Context) {
	fmt.Println()
	fmt.Println("Access token:")
	fmt.Println(loginContext.Value(accessTokenKey))
}

func deviceLogin() (*ssoclient.LoginResult, error) {
	return ssoclient.LoginWithDeviceAuth(
		"http://localhost:8080/realms/test/protocol/openid-connect/auth/device",
		"http://localhost:8080/realms/test/protocol/openid-connect/token",
		"test",
		func(verificationURI, userCode string) {
			fmt.Println("Login URL: " + verificationURI)
			fmt.Println("User code: " + userCode)
		},
	)
}

func authCodeLogin() (*ssoclient.LoginResult, error) {
	return ssoclient.LoginWithOIDCProxy(
		"http://localhost:8000/cli-login",
		func(loginURL string) {
			fmt.Printf("Login at: %s\n", loginURL)
		},
	)
}

func main() {
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	grant := loginCmd.String("grant", "code", "SSO Authentication grant (code/device)")

	if len(os.Args) < 2 {
		fmt.Println("CLI utility for SSO login")
		os.Exit(0)
	}

	switch os.Args[1] {
	case "login":
		loginCmd.Parse(os.Args[2:])
		var loginResult *ssoclient.LoginResult
		var err error
		if *grant == "device" {
			loginResult, err = deviceLogin()
		} else if *grant == "code" {
			loginResult, err = authCodeLogin()
		} else {
			fmt.Printf("Invalid value for arg 'grant': %s\n", *grant)
			os.Exit(1)
		}
		if err != nil {
			fmt.Printf("Could not login: %s\n", err.Error())
			os.Exit(1)
		}

		// TODO: implement refreshing token
		// TODO: implement refresh token handler in ssoproxy
		ctx := context.Background()
		ctx = context.WithValue(ctx, accessTokenKey, loginResult.AccessToken)
		vaultAuth(ctx)
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
