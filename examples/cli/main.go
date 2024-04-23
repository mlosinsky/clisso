package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mlosinsky/clisso/ssoclient"
)

func deviceLogin(oidcTokenURI, oidcDeviceURI, clientId string) (*ssoclient.LoginResult, error) {
	return ssoclient.LoginWithDeviceAuth(
		ssoclient.DeviceAuthConfig{
			DeviceAuthURI: oidcDeviceURI,
			TokenURI:      oidcTokenURI,
			ClientId:      clientId,
		},
		func(verificationURI, userCode string) {
			fmt.Println("Login at: ", verificationURI)
			fmt.Println("User code:", userCode)
		},
	)
}

func proxyLogin(proxyLoginURI string) (*ssoclient.LoginResult, error) {
	return ssoclient.LoginWithSSOProxy(
		proxyLoginURI,
		func(loginURL string) {
			fmt.Println("Login at:", loginURL)
		},
	)
}

func loginCommand(grant, oidcTokenURI, oidcDeviceURI, clientId, proxyLoginURI string) error {
	if grant == "device" {
		if oidcTokenURI == "" || oidcDeviceURI == "" || clientId == "" {
			return errors.New("'oidc-uri' and 'client-id' are required for device auth")
		}
		if loginResult, err := deviceLogin(oidcTokenURI, oidcDeviceURI, clientId); err != nil {
			return err
		} else {
			fmt.Printf("%+v\n", loginResult)
		}
	} else if grant == "code" {
		if proxyLoginURI == "" {
			return errors.New("'login-uri' is required for code auth")
		}
		if loginResult, err := proxyLogin(proxyLoginURI); err != nil {
			return err
		} else {
			fmt.Printf("%+v\n", loginResult)
		}
	} else {
		return fmt.Errorf("invalid 'grant': %s", grant)
	}
	return nil
}

func main() {
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	grant := loginCmd.String("grant", "code", "SSO Authentication grant (code/device)")
	oidcTokenURI := loginCmd.String("token-uri", "", "Token URI for OpenID Connect API (used only for 'device' grant)")
	oidcDeviceURI := loginCmd.String("device-uri", "", "Device auth URI for OpenID Connect API (used only for 'device' grant)")
	clientId := loginCmd.String("client-id", "", "OpenID Connect client id (used only for 'device' grant)")
	proxyLoginURI := loginCmd.String("login-uri", "", "SSO Proxy login URI (used only for 'code' grant)")

	if len(os.Args) < 2 {
		fmt.Println("CLI SSO login")
		os.Exit(0)
	}

	switch os.Args[1] {
	case "login":
		loginCmd.Parse(os.Args[2:])
		if err := loginCommand(*grant, *oidcTokenURI, *oidcDeviceURI, *clientId, *proxyLoginURI); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
