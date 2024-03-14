package ssoclient

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const EVENT_AUTH_URL = "auth-url"
const EVENT_OIDC_TOKENS = "oidc-tokens"
const EVENT_ERROR = "error"

func LoginWithOIDCProxy(
	proxyLoginURL string,
	onLoginURLReceived func(loginURL string),
) (accessToken, refreshToken string, err error) {
	req, err := http.NewRequest("GET", proxyLoginURL, nil)
	if err != nil {
		return "", "", errors.Join(errors.New("failed to create HTTP login request"), err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", errors.Join(errors.New("failed to execute HTTP login request"), err)
	}
	if res.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP login response status was %d, expected 200", res.StatusCode)
	}
	defer res.Body.Close()
	err = consumeSSEFromHTTPEventStream(
		res.Body,
		func(event, data string) error {
			if event == EVENT_AUTH_URL {
				onLoginURLReceived(data)
			} else if event == EVENT_OIDC_TOKENS {
				// TODO: parse JSON
				accessToken = "access"
				refreshToken = "refresh"
				return nil
			} else if event == EVENT_ERROR {
				return fmt.Errorf("received error '%s'", data)
			} else {
				return fmt.Errorf("encountered unkown login event '%s'", event)
			}
			return nil
		},
	)
	return accessToken, refreshToken, err
}

// Takes an HTTP response body of a response with text/event-stream Content-Type
// and consumes Server-Sent Events (SSE) that were sent through the HTTP connection.
func consumeSSEFromHTTPEventStream(
	httpBody io.ReadCloser,
	onEventReceived func(event, data string) error,
) error {
	scanner := bufio.NewScanner(httpBody)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		// if scanner has nothing to scan, continue scanning
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		// if data contains two line ends (end of an event) hand in the whole event
		twoLineEnds := bytes.Index(data, []byte("\n\n"))
		if twoLineEnds >= 0 {
			return twoLineEnds + 2, data[0:twoLineEnds], nil
		}
		// if scanner is at EOF hand in the rest of the data
		// TODO: the scanner will always receive a whole event, is this necessary?
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for {
		if scanner.Scan() {
			rawEvent := scanner.Text()
			event, data, err := parseSSEEvent(rawEvent)
			if err != nil {
				return errors.Join(errors.New("received invalid login event from proxy"), err)
			}
			if err = onEventReceived(event, data); err != nil {
				return errors.Join(errors.New("an error occurred during consuming a login event"), err)
			}
		} else {
			if err := scanner.Err(); err != nil {
				return errors.Join(errors.New("an error occurred while reading login events"), err)
			} else {
				return nil
			}
		}
	}
}

// parses Server-Sent Events (SSE) event and validates its structure.
func parseSSEEvent(rawEvent string) (event, data string, err error) {
	parts := strings.Split(rawEvent, "\n")
	if len(parts) != 2 {
		return "", "", errors.New("event does not contain one or both fields 'event' and 'data' or has more fields")
	}
	event, valid := strings.CutPrefix(parts[0], "event: ")
	if !valid {
		return "", "", errors.New("SSE event field 'event' must start with 'event: '")
	}
	data, valid = strings.CutPrefix(parts[1], "data: ")
	if !valid {
		return "", "", errors.New("SSE event field 'data' must start with 'data: '")
	}
	return event, data, nil
}
