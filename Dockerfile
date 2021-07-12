FROM golang:1.16 AS builder

WORKDIR /go/src/app

COPY go.mod .
COPY main.go .
RUN go get -d -v

ENV CGO_ENABLED=0
RUN go build -o /go/bin/photobackup

FROM alpine

WORKDIR /app
COPY --from=builder /go/bin/photobackup /app/photobackup

ENTRYPOINT ["/app/photobackup", "/data/.photobackup"]