package ssoclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type DeviceAuthConfig struct {
	// URI to OAuth device auth endpoint
	DeviceAuthURI string
	// URI to OAuth token endpoint
	TokenURI string
	// OAuth client id
	ClientId string
	// Optional OAuth scope, uses "openid" by default and adds this value to it
	Scope string
}

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenErrorResponse struct {
	Error string `json:"error"`
}

type tokenSuccessResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

const authorizationPendingError = "authorization_pending"
const slowDownError = "slow_down"
const accessDeniedError = "access_denied"
const expiredTokenError = "expired_token"

// Starts the login process using OAuth 2.0 Device Grant.
// This login flow doesn't require a proxy, but OAuth 2.0 Device Grant must be enabled on the IdP.
// The client must also be able to reach the IdP.
//
//	The flow performs these steps:
//	1. Calls Device Authorization Endpoint and receives device code, user code and verification URI
//	2. The verification URI will be passed to verificationURIReceived func
//	3. While waiting for user to log in, IdP /token endpoint will be polled
//	4. After user logs in the poll attempt will be successful returning access and refresh token
//	5. These tokens will be returned to the function caller
//
// After successful login OIDC access and refresh tokens are returned.
func LoginWithDeviceAuth(
	config DeviceAuthConfig,
	verificationURIReceived func(verificationURI, userCode string),
) (*LoginResult, error) {
	deviceRes, err := callDeviceAuthorizationEndpoint(config.DeviceAuthURI, config.ClientId, config.Scope)
	if err != nil {
		return nil, err
	}
	verificationURIReceived(deviceRes.VerificationURI, deviceRes.UserCode)
	if deviceRes.Interval == 0 {
		// Poll interval is optional in Device Authorization RFC and if not defined, 5s should be used
		deviceRes.Interval = 5
	}
	tokenRes, err := pollTokensEndpoint(
		deviceRes.DeviceCode,
		config.ClientId,
		config.TokenURI,
		deviceRes.Interval,
		deviceRes.ExpiresIn,
	)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		AccessToken:  tokenRes.AccessToken,
		RefreshToken: tokenRes.RefreshToken,
		Expiration:   tokenRes.ExpiresIn,
	}, nil
}

// Issues an HTTP GET for Device Authorization.
func callDeviceAuthorizationEndpoint(OAuthDeviceAuthURI, clientId, scope string) (*deviceAuthResponse, error) {
	res, err := http.PostForm(OAuthDeviceAuthURI, url.Values{
		"client_id": {clientId},
		"scope":     {fmt.Sprintf("%s openid", scope)},
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to execute Device Authorization request"), err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to execute Device Authorization request, response status was %d, expected 200", res.StatusCode)
	}
	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Join(errors.New("failed to read response body of Device Authorization request"))
	}
	defer res.Body.Close()

	var body deviceAuthResponse
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return nil, errors.New("received Device Authorization endpoint response body in invalid format")
	}
	return &body, nil
}

// Polls the OAuth 2.0 Token endpoint according to Device Authorization Grant RFC.
func pollTokensEndpoint(
	deviceCode string,
	clientId string,
	OAuthTokenURI string,
	pollInterval int,
	maxPollTime int,
) (*tokenSuccessResponse, error) {
	timePassed := 0
	for timePassed <= maxPollTime {
		time.Sleep(time.Second * time.Duration(pollInterval))
		timePassed += pollInterval

		res, err := http.PostForm(OAuthTokenURI, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {clientId},
		})
		if err != nil {
			return nil, errors.Join(errors.New("an error occurred while after polling /token endpoint"), err)
		}

		rawResBody, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Join(errors.New("failed to read body of /token endpoint response"))
		}

		if res.StatusCode == http.StatusOK {
			var resBody tokenSuccessResponse
			if err := json.Unmarshal([]byte(rawResBody), &resBody); err != nil {
				return nil, errors.New("received invalid format of success poll response, could not deserialize JSON body")
			}
			return &resBody, nil
		}

		var resBody tokenErrorResponse
		if err := json.Unmarshal([]byte(rawResBody), &resBody); err != nil {
			return nil, errors.New("received invalid format of error poll response, could not deserialize JSON body")
		}
		res.Body.Close() // defer would execute after function return

		if resBody.Error == slowDownError {
			pollInterval += 5 // implemeted according to Device Auth RFC
		} else if resBody.Error == accessDeniedError {
			return nil, errors.New("can't poll /token endpoint, access was denied")
		} else if resBody.Error == expiredTokenError {
			return nil, errors.New("authorization attempt expired")
		} else if resBody.Error != authorizationPendingError {
			return nil, fmt.Errorf("received unknown error code %s while polling for access and refresh token", resBody.Error)
		}
	}
	return nil, errors.New("authorization attempt expired")
}
