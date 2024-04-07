package ssoclient

// Simple login result type returned from all login functions.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	// expires_in field from /token endpoint
	Expiration int
}
