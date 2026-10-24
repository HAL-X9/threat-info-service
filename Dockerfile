FROM golang:1.27-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /build/server ./cmd

FROM alpine:3.24

RUN adduser -D -u 1001 app

WORKDIR /app

COPY --from=builder --chown=app:app /build/server .
COPY --chown=app:app configs ./configs

USER app

EXPOSE 8080

ENTRYPOINT ["/app/server"]
