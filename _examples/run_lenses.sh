#!/bin/sh

# Run Minikube
minikube delete
minikube config set cpus 4
minikube config set memory 5120
minikube start

# Run Kafka
kubectl create -f k8s-kafka.yml
echo Waiting 5 minutes...
sleep 300 # wait for Kafka container to be created

# Create secrets
# IMPORTANT! Remember to copy lenses license.json to dir
kubectl create secret generic lenses-secrets --from-file=./LENSES_SECURITY_USERS --from-file=./LENSES_SECURITY_GROUPS --from-file=./license.json

# Run Lenses
kubectl create -f k8s-lenses.yml
echo Waiting 2 minutes...
sleep 120 # wait for Lenses container to be created

# Get Lenses URL
echo Lenses URL:
minikube service lenses --url


