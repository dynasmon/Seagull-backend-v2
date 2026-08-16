ARG GO_VERSION=1.25.0

FROM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG COMPONENT
ARG VERSION=dev
ARG REVISION=unknown

RUN test -n "${COMPONENT}" && test -d "./cmd/${COMPONENT}"
RUN CGO_ENABLED=0 GOFLAGS=-mod=readonly go build \
    -trimpath \
    -ldflags "-s -w \
      -X github.com/dynasmon/Seagull-v2/internal/platform/buildinfo.version=${VERSION} \
      -X github.com/dynasmon/Seagull-v2/internal/platform/buildinfo.revision=${REVISION}" \
    -o /out/component "./cmd/${COMPONENT}"

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/component /usr/local/bin/component

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/component"]
