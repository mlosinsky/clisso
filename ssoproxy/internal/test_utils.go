package internal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

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

func ConsumeSSEFromHTTPEventStream(
	httpBody io.ReadCloser,
	onEventReceived func(event, data string) error,
) error {
	scanner := bufio.NewScanner(httpBody)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		twoLineEnds := bytes.Index(data, []byte("\n\n"))
		if twoLineEnds >= 0 {
			return twoLineEnds + 2, data[0:twoLineEnds], nil
		}
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

func CreateMockOIDCServer(expectedAuthCode, expectedClientId, expectedClientSecret, expectedRedirectURI string) httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, fmt.Sprintf("Invalid grant_type: %s", r.Form.Get("grant_type")), http.StatusBadRequest)
		} else if r.Form.Get("code") != expectedAuthCode {
			http.Error(w, fmt.Sprintf("Invalid code %s, expected %s", r.Form.Get("code"), expectedAuthCode), http.StatusBadRequest)
		} else if r.Form.Get("client_id") != expectedClientId {
			http.Error(w, fmt.Sprintf("Invalid client_id %s, expected %s", r.Form.Get("client_id"), expectedAuthCode), http.StatusBadRequest)
		} else if r.Form.Get("client_secret") != expectedClientSecret {
			http.Error(w, fmt.Sprintf("Invalid client_secret %s, expected %s", r.Form.Get("client_secret"), expectedClientSecret), http.StatusBadRequest)
		} else if r.Form.Get("redirect_uri") != expectedRedirectURI {
			http.Error(w, fmt.Sprintf("Invalid redirect_uri %s, expected %s", r.Form.Get("redirect_uri"), expectedRedirectURI), http.StatusBadRequest)
		}
		w.Write([]byte(`{"access_token":"mock-access-token","refresh_token":"mock-refresh-token"}`))
	})
	return *httptest.NewServer(mux)
}
