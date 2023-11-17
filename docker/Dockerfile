FROM golang:1.21 as deps
WORKDIR /
COPY go.* ./
RUN go mod download

FROM deps as build
COPY . .
RUN make build

FROM gcr.io/distroless/base-debian12:latest
COPY --from=build /build/cert-scanner /bin
CMD ["/bin/cert-scanner"]