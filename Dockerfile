FROM caddy:builder-alpine AS builder

RUN apk add --update --no-cache make

ADD . .
RUN make build

# FINAL IMAGE
FROM caddy:alpine

COPY --from=builder /usr/bin/out/caddy /usr/bin/caddy