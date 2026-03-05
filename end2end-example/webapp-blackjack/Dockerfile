FROM golang:1.24-bookworm AS builder

WORKDIR /src

COPY compilers/go/go.mod compilers/go/go.sum compilers/go/
COPY end2end-example/webapp-blackjack/go.mod end2end-example/webapp-blackjack/go.sum end2end-example/webapp-blackjack/

WORKDIR /src/end2end-example/webapp-blackjack
RUN go mod download

WORKDIR /src
COPY compilers/go/ compilers/go/
COPY end2end-example/webapp-blackjack/ end2end-example/webapp-blackjack/

WORKDIR /src/end2end-example/webapp-blackjack
RUN CGO_ENABLED=1 go build -o /script21 .

FROM scratch
COPY --from=builder /script21 /script21
