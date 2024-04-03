#!/bin/bash

echo 'Install curl'
apt-get -qq update >/dev/null
apt-get -qq upgrade >/dev/null
apt-get install -y curl -qq >/dev/null

until curl -s -f -o /dev/null "http://keycloak:8080/realms/test"
do
  echo 'Waiting for Keycloak to start...'
  sleep 5
done

echo 'Enable JWT auth method'
body='
{
  "type": "jwt",
  "description": "Login with JWT from Keycloak"
}
'
echo $body | curl --request POST http://vault:8200/v1/sys/auth/jwt \
    --header "Content-Type: application/json" \
    --header "X-Vault-Token: root" \
    --data @-
    

echo 'Configure vault JWT auth method to Keycloak'
body='
{
  "oidc_discovery_url": "http://keycloak:8080/realms/test",
  "default_role": "demo"
}
'
echo $body | curl --request POST http://vault:8200/v1/auth/jwt/config \
   --header "Content-Type: application/json" \
   --header "X-Vault-Token: root" \
   --data @-

echo 'Create a named role'
body='
{
  "role_type": "jwt",
  "ttl": "1h",
  "token_policies": "webapps",
  "bound_subject": "852f176b-25ff-49e8-869d-276f37389718",
  "allowed_redirect_uris": "http://sso-proxy:8000/cli-logged-in",
  "user_claim": "vault_user"
}
'
echo $body | curl --request POST http://vault:8200/v1/auth/jwt/role/test \
   --header "Content-Type: application/json" \
   --header "X-Vault-Token: root" \
   --data @-
