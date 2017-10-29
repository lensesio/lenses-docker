#!/usr/bin/env bash

if [[ -z $LENSES_PORT ]]; then
    export LENSES_PORT='9991'
    echo "Setting LENSES_PORT=9991. Override by setting the environment variable."
fi
if [[ -z $LENSES_KAFKA_BROKERS ]]; then
    export LENSES_KAFKA_BROKERS='"PLAINTEXT://localhost:9092"'
    echo "Setting LENSES_KAFKA_BROKERS='\"PLAINTEXT://localhost:9092\"'. Override by setting the environment variable."
fi
if [[ -z $LENSES_ZOOKEEPER_HOSTS ]]; then
    export LENSES_ZOOKEEPER_HOSTS='"localhost:2181"'
    echo "Setting LENSES_ZOOKEEPERS='\"localhost:2181\"'. Override by setting the environment variable."
fi
if [[ -z $LENSES_SCHEMA_REGISTRY_URLS ]]; then
    export LENSES_SCHEMA_REGISTRY_URLS='"http://localhost:8081"'
    echo "Setting LENSES_SCHEMA_REGISTRY_URLS='\"http://localhost:8081\"'. Override by setting the environment variable."
fi
if [[ -z $LENSES_CONNECT ]]; then
    export LENSES_CONNECT='[{default:"http://localhost:8083"}]'
    echo "Setting LENSES_CONNECT='[{default:\"http://localhost:8083\"}]'. Override by setting the environment variable."
fi
if [[ -z $LENSES_JMX_BROKERS ]]; then
    # LENSES_JMX_BROKERS="localhost:9581"
    echo "LENSES_JMX_BROKERS is not set. Some functionality won't be available."
fi
if [[ -z $LENSES_JMX_SCHEMA_REGISTRY ]]; then
    # LENSES_JMX_SCHEMA_REGISTRY="localhost:9582"
    echo "LENSES_JMX_SCHEMA_REGISTRY is not set. Some functionality won't be available."
fi
if [[ -z $LENSES_JMX_ZOOKEEPERS ]]; then
    # LENSES_JMX_ZOOKEEPERS="localhost:9585"
    echo "LENSES_JMX_ZOOKEEPERS is not set. Some functionality won't be available."
fi
if [[ -z $LENSES_JMX_CONNECT ]]; then
    # LENSES_JMX_CONNECT='[{default:"localhost:9584"}]'
    echo "LENSES_JMX_CONNECT is not set. Some functionality won't be available."
fi
if [[ -z $LENSES_SECURITY_USERS ]]; then
   export LENSES_SECURITY_USERS='[{"username": "admin", "password": "admin", "displayname": "Lenses Admin", "roles": ["admin", "write", "read"]}]'
   echo "LENSES_SECURITY_USERS is not set. Setting default user 'admin' with password 'admin'."
fi

for var in $(printenv | grep LENSES | sed -e 's/=.*//'); do
    # to lowercase
    conf="${var,,}"
    # underscore to stop
    conf="${conf//_/.}"
    echo "${conf}=${!var}"
    echo "${conf}=${!var}" >> /lenses.conf
done

echo "lenses.license.file=/license.json" >> /lenses.conf


exec /opt/lenses/bin/lenses /lenses.conf

