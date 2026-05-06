ARG GOLANG_VERS=1.21
ARG ALPINE_VERS=3.19

FROM golang:${GOLANG_VERS}-alpine${ALPINE_VERS}

ARG CGO_ENABLED=1
ARG COREDNS_VERS=1.10.1

RUN apk --no-cache add build-base git binutils

RUN git clone --depth 1 --branch v${COREDNS_VERS} https://github.com/coredns/coredns.git /coredns
WORKDIR /coredns
RUN go mod download

COPY ./ /plugin/dockerdiscovery
RUN sed -i "s/^#.*//g; /^$/d; /^hosts:hosts$/i docker:dockerdiscovery" plugin.cfg \
    && go mod edit -replace \
    dockerdiscovery=/plugin/dockerdiscovery \
    && go generate coredns.go \
    && go build -mod=mod -o=/usr/local/bin/coredns \
    && strip -vs /usr/local/bin/coredns

FROM alpine:${ALPINE_VERS}
# ca-certificates: TLS to Cloudflare/Docker APIs
# iproute2 (ss), curl, netcat-openbsd (nc): for `docker exec` debugging of the
# inventory HTTP endpoint — see README "Debugging the endpoint".
RUN apk --no-cache add ca-certificates iproute2 curl netcat-openbsd bash
COPY --from=0 /usr/local/bin/coredns /usr/local/bin/coredns
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
