FROM golang:1.21.3 as deps
WORKDIR /cert-scanner
COPY cert-scanner/go.* /cert-scanner
RUN go mod download

FROM deps as build
WORKDIR /cert-scanner
COPY . /cert-scanner
RUN ls -al /cert-scanner && make generate test build

FROM gcr.io/distroless/static-debian12 as runtime
COPY --from=build /cert-scanner /bin/
EXPOSE 8080
ENTRYPOINT [ "/bin/cert-scanner" ]