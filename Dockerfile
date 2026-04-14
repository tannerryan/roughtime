# roughtime - https://github.com/tannerryan/roughtime

# Builder
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
RUN go mod verify
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor \
    go build -trimpath -ldflags="-s -w" -o /roughtime .

# Image
FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="roughtime" \
      org.opencontainers.image.source="https://github.com/tannerryan/roughtime"
COPY --from=build /roughtime /roughtime
EXPOSE 2002/udp
ENTRYPOINT ["/roughtime"]
