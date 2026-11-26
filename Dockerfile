# Builder: vendored dependencies, static binary, stripped symbols.
FROM golang:1.27 AS build
ARG COMMIT=""
ARG BUILD_DATE=""
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor \
    go build -trimpath \
        -ldflags="-s -w \
            -X github.com/tannerryan/roughtime/internal/version.Commit=${COMMIT} \
            -X github.com/tannerryan/roughtime/internal/version.Date=${BUILD_DATE}" \
        -o /roughtime ./cmd/roughtime

# Runtime: distroless nonroot, primary port 5319 and optional compatibility port 2002.
FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.title="roughtime" \
    org.opencontainers.image.source="https://github.com/tannerryan/roughtime" \
    org.opencontainers.image.licenses="BSD-2-Clause"
COPY --from=build /roughtime /roughtime
COPY --from=build /src/LICENSE /licenses/roughtime/LICENSE
COPY --from=build /src/vendor/go.uber.org/zap/LICENSE /licenses/zap/LICENSE
COPY --from=build /src/vendor/go.uber.org/multierr/LICENSE.txt /licenses/multierr/LICENSE.txt
COPY --from=build /src/vendor/golang.org/x/net/LICENSE /src/vendor/golang.org/x/net/PATENTS /licenses/x-net/
COPY --from=build /src/vendor/golang.org/x/sys/LICENSE /src/vendor/golang.org/x/sys/PATENTS /licenses/x-sys/
EXPOSE 5319/udp
EXPOSE 5319/tcp
EXPOSE 2002/udp
EXPOSE 2002/tcp
ENTRYPOINT ["/roughtime"]
