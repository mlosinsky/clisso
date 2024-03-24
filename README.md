# Go Single Sign-On for Console applications

Features that need to be implemented before v1:
- write tests for ssoclient and e2e_tests
- e2e_test with keycloak and vault
- e2e_test with different IdP (not keycloak)
- CI - test ssoproxy(+coverage), ssoclient(+coverage), e2e_tests
- CI - version release 
  - tag ssoproxy/vX.X.X and ssoclient/vX.X.X, vX.X.X (for helm chart)
- refactor and write doc strings
- README.md - info, install, how to use, show coverage
- refactor CLI example and proxy example
- Helm chart for proxy example
- cleanup/remove local/ directory