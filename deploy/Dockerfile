FROM golang:1.26.11-trixie@sha256:fa340cb59ebeb1d53ac1cccfc334201d938fe5f3458003cccb767096d8e032b8 AS build

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
      -X github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo.version=${VERSION} \
      -X github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo.revision=${REVISION}" \
    -o /out/component "./cmd/${COMPONENT}"

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/component /usr/local/bin/component

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/component"]
