This is a brief example for running Lenses in a minikube kubernetes cluster.  We
create a Kafka service using `landoop/fast-data-dev` image, then setup a Lenses
service to access Kafka. We demonstrate how to use secrets, in order to protect
sensitive info.

For the example to work, you need to add your `license.json` to this directory.

To run the example you probably have to destroy your minikube cluster and create
a new with enough memory. Please evaluate the commands and decide whether you need
to create a new minikube cluster.

    # Setup minikube
    minikube delete
    minikube config set cpus 4
    minikube config set memory 5120
    minikube start

    # Create Kafka (please wait a bit for Kafka to start before starting Lenses)
    kubectl create -f k8s-kafka.yml
    
    # Create Secrets (remember to add license.json to this directory)
    kubectl create secret generic lenses-secrets --from-file=./LENSES_SECURITY_USERS --from-file=./license.json
    
    # Create Lenses (needs a few seconds to start)
    kubectl create -f k8s-lenses.yml
    
    # Checkout Lenses. Default admin credentials are admin/admin
    minikube service lenses --url
    
    # Once finished, clean up
    kubectl delete service lenses kafka fast-data-dev-ui
    kubectl delete pod lenses kafka
    minikube stop
