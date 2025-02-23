#!/bin/bash

create_ns() {
    kubectl get ns $1 2&>1 > /dev/null
    if [[ $? != 0 ]]; then
      kubectl create ns $1
    fi
}

kind get clusters | grep cert-scanner > /dev/null || kind create cluster --name cert-scanner
create_ns monitoring
create_ns security-scanners

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 
helm upgrade --install prometheus charts/prometheus --namespace monitoring --values charts/prometheus/values.yaml