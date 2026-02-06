# Cert-scanner-darkly

A network scanner to monitor TLS enabled endpoints to check their certs for compliance to various vaidation rules. The scanner uses various discovery mechanisms to detect running target services. It will attempt to establish a TLS connnection to each each target it discovers. If a connection is established, the certificate gets extracted and various validations are applied like validity windows, tls versions, trust chain etc. Finally targets are passed through a series of reporters document the outcome of the scan and allow for violations to be actioned

# Building

The project uses [ko](https://github.com/ko-build/ko) to build a container image containing the scanner binary. To build the image run `make build`

# Testing

To run the test suite run `make tests` this will build and run a suite of unit tests with test coverage. To test the app locally the project uses [kind](https://kind.sigs.k8s.io/). Once kind is installed, the `make bootstrap` task will configure a test kubernetes cluster and deploy a single replica of the cert-scanner to this cluster.

To build and deploy a new version to this cluster for testing run the target `make local-dev`. See canary below for an app that exposes a number of configuration violations.

# Configuring and Running.

The scanner takes it's configuration via a cli flag. Examples of the various configuration options can be found in the chart [values.yaml](charts/cert-scanner/values.yaml) or in [example/config.yaml](/example/config.yaml)

```
cert-scanner -c /path/to/cert-scanner-config.yaml
```

The scanner can be run locally as above, but is most useful when deployed to run continually and the helm chart in the [charts](/charts/cert-scanner/) folder can be used to deploy the scanner into a kubernetes cluster. Configuration for the chart, to enable various validations and reporters is found in [values.yaml](charts/cert-scanner/values.yaml). This can be deployed into the current cluster via `make deploy`. The default configuration will scan for ready pods. It will attempt to establish a TLS connection.

# Architecture

There are 4 distinct phases to a scan, currently each phase runs to completion before the next stage starts. Within each stage individual items are executed in parallel.

## Discovery
During the discovery phase, all of the configured discovery sources are queried for Targets to scan. Targets come in 2 flavors, an ip:port or a url, and each contains a source and a source type. Discoveries can add arbitrary labels to a target which can be used when reporting violations later.

### Kubernetes

The kubernetes discovery mechanism will connect to the cluster in the current context and list all the ready pods, extracting pod-ip:port pairs and creating a Target for each, with 'kubernetes' as the sourcetype  and the cluster name as the source.

#### K8s filtering
Discovered pods are fed through a set of configured ignore filters that use the jsonpath functionality from the k8s client to match against the pod content for fields. The matching sections are tested against configured regexes and any matches are ignored for the scan.

 Filters are broken into two sections ignore_pods and ignore_containers;
 - ignore_pods will discard any pods that match a given filter where as
 - ignore_containers will allow sidecars and container level ports to be ignored.

 e.g.
 ```
ignore_pods:
  - pattern: "{.metadata.namespace}"
    match:
      - some-namespace
ignore_containers:
  - pattern: "{.spec.containers[*].ports[*].name}"
    match:
      - metrics
      - healthz
```

### File

File discovery loads static urls from host files, creating a Target for each url found in the file. Host entries are grouped within the file and the group key is used as the source. The source type will be file.

## Processing
Once all the targets have been discovered, they each need to be processed. There is currently only a single processor in this phase and is used to connect to each target and extract tls state. The processor gets configured with a number of ciphers and tls versions. It iterates over the tls versions and for each appropriate cipher it will try to negotiate a connection to the target with each version/cipher pair and will extract the tls state from the connection, including the certificate into a result. If the Target cannot be connected to or fails a tls handshake then this is captured instead. Either way, the result of connecting to the Target using the version/cipher pair gets stored in the scan for validation/reporting.

## Validation
Once all targets have been scanned and the results gathered they can be validated for rule violations. Validations get passed each Target and iterate over the contained results to validate their rule. There are 5 kinds of validation, each examining the TLS certificate extracted during the processing phase. If a validation fails it will add a number of labels to the result that will be used during reporting.

### NotYetValid
Checks if the NotBefore date on the retrieved certificate is in the future. If so it raise a NotYetValidViolation tracking the not before date nd the time until the cert is valid as labels.

### Expired
The expiry validation gets configured with a warning duration and when the current time is within this duration of the cert's expiry time a violation gets raised. The violation contains the warning duration and the cert expiry time as labels.

### TLS Version
The version validation is configured with a min acceptable tls version. If the tls version of a result is less than the acceptable version then a violation is raised. The violation contains the min tls and extracted tls versions as labels

### Trust Chain
The Trust Chain validation will check that trust chains of retrieved certs are valid. By default it will defer to the system bundle but can be configured to ignore this and use one or more CA bundles containing custom root CA certs. Each cert is validated using the configured CA bundles and will raise a violation if the full chain of trust for the cert cannot be verified. Violations will contain subject_cn, issuer cn and the authority key id.


## Reporting

Each configured reported gets a chance to report on the scan of each target where they can make use of any labels gathered from the source or validations.

## Logging

The logging reporter will log each scan violation to the given log file on disk. It is configured via a logging block in the reporters stanza of the [config](example/config.yaml) e.g.

```yaml
reporters:
  logging:
    enabled: true
    path: /path/to/some/file
```

If no path is specified then it will log to stdout which is useful when the scanner runs in k8s.

## Metrics

There are a number of reporters that increment prometheus counter metrics for each violation, one for each validation type. These will emit the labels gathered when incrementing the counter


### NotYetValid
NotYetValid violations increment a counter `certificate_not_yet_valid_validations_total`

### Expired
Expiry violations increment a counter `certificate_expiry_validations_total`

### TLS Version
TLS Version violations increment a counter `tls_version_validations_total`

### Trust Chain
Trust chain violations `trust_chain_validations_total`
