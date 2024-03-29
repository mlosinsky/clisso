package ssoclient

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	// expires_in field from /token endpoint
	Expiration int
}
