FROM golang:1.24-bookworm AS builder

WORKDIR /src

COPY compilers/go/go.mod compilers/go/go.sum compilers/go/
COPY examples/end2end-example/webapp-blackjack/go.mod examples/end2end-example/webapp-blackjack/go.sum examples/end2end-example/webapp-blackjack/

WORKDIR /src/examples/end2end-example/webapp-blackjack
RUN go mod download

WORKDIR /src
COPY compilers/go/ compilers/go/
COPY examples/end2end-example/webapp-blackjack/ examples/end2end-example/webapp-blackjack/

WORKDIR /src/examples/end2end-example/webapp-blackjack
RUN CGO_ENABLED=1 go build -o /script21 .

FROM scratch
COPY --from=builder /script21 /script21
