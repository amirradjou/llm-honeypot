# Build a static binary, then ship it on distroless. No shell, no package
# manager, nothing for an attacker to reach even in the unlikely event
# they break out of the fake shell (which never executes anything anyway).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeypot ./cmd/honeypot
RUN mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/honeypot /honeypot
# /data must be writable by the nonroot user the image runs as.
COPY --from=build --chown=nonroot:nonroot /data /data
# The fake SSH server listens here; map it to :22 on the host with care,
# and only on a machine that does not matter.
EXPOSE 2222
VOLUME ["/data"]
ENV HONEYPOT_ADDR=":2222" HONEYPOT_DATA_DIR="/data" HONEYPOT_LOG_JSON="1"
ENTRYPOINT ["/honeypot"]
