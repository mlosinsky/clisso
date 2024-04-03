# syntax=docker/dockerfile:1

FROM golang:1.21.6 AS build-stage
WORKDIR /app
COPY *.go go.mod go.sum ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /sso-proxy

FROM gcr.io/distroless/base-debian11
WORKDIR /
COPY --from=build-stage /sso-proxy /sso-proxy
EXPOSE 8000
USER nonroot:nonroot
ENTRYPOINT ["/sso-proxy"]