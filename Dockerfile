FROM caddy:2.8-builder-alpine AS builder

RUN apk add --update --no-cache make

ADD . .
RUN make build

# FINAL IMAGE
FROM caddy:2.8-alpine

COPY --from=builder /usr/bin/out/caddy /usr/bin/caddy