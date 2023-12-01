FROM golang:1.21 as deps
WORKDIR /
COPY cert-scanner/go.* /
RUN go mod download

FROM deps as build
COPY cert-scanner/ /
RUN CGO_ENABLED=0 go build -o cert-scanner main/main.go

FROM gcr.io/distroless/static-debian12 as runtime
COPY --from=build /cert-scanner /bin/
EXPOSE 8080
ENTRYPOINT [ "/bin/cert-scanner" ]