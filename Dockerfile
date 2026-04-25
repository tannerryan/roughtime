# Distroless image for the Roughtime server binary. Source:
# https://github.com/tannerryan/roughtime

# Builder: vendored, static, stripped.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
RUN go mod verify
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor \
    go build -trimpath -ldflags="-s -w" -o /roughtime ./server

# Runtime: distroless nonroot, UDP/TCP 2002.
FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="roughtime" \
    org.opencontainers.image.source="https://github.com/tannerryan/roughtime"
COPY --from=build /roughtime /roughtime
EXPOSE 2002/udp
EXPOSE 2002/tcp
ENTRYPOINT ["/roughtime"]
