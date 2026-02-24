ARG GOLANG_VERS=1.21
ARG ALPINE_VERS=3.19

FROM golang:${GOLANG_VERS}-alpine${ALPINE_VERS}

ARG CGO_ENABLED=1
ARG PLUGIN_PRIO=57
ARG COREDNS_VERS=1.10.1

RUN apk --no-cache add build-base git binutils

RUN git clone --depth 1 --branch v${COREDNS_VERS} https://github.com/coredns/coredns.git /coredns
WORKDIR /coredns
RUN go mod download

COPY ./ /plugin/dockerdiscovery
RUN sed -i "s/^#.*//g; /^$/d; ${PLUGIN_PRIO} i docker:dockerdiscovery" plugin.cfg \
    && go mod edit -replace \
    dockerdiscovery=/plugin/dockerdiscovery \
    && go generate coredns.go \
    && go build -mod=mod -o=/usr/local/bin/coredns \
    && strip -vs /usr/local/bin/coredns

FROM alpine:${ALPINE_VERS}
RUN apk --no-cache add ca-certificates
COPY --from=0 /usr/local/bin/coredns /usr/local/bin/coredns
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
