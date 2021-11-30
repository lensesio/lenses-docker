#!/usr/bin/env bash

set -e
set -u
set -o pipefail

FASTDATA_SD=/usr/local/bin/fastdata-sd

SD_CONFIG=${SD_CONFIG:-}

SD_BROKER_FILTER=${SD_BROKER_FILTER:-}
SD_BROKER_PORT=${SD_BROKER_PORT:-9092}
SD_BROKER_PROTOCOL=${SD_BROKER_PROTOCOL:-PLAINTEXT}

SD_ZOOKEEPER_FILTER=${SD_ZOOKEEPER_FILTER:-}
SD_ZOOKEEPER_PORT=${SD_ZOOKEEPER_PORT:-2181}
SD_ZOOKEEPER_JMX_PORT=${SD_ZOOKEEPER_JMX_PORT:-}

rm -f /tmp/sd-broker /tmp/sd-zookeeper /tmp/service-discovery /tmp/service-discovery.log

if [[ -n $SD_BROKER_FILTER ]]; then
    if $FASTDATA_SD \
           -mode=broker -port=$SD_BROKER_PORT -protocol="$SD_BROKER_PROTOCOL" \
           addrs $SD_CONFIG \
           $SD_BROKER_FILTER >/tmp/sd-broker 2>/tmp/service-discovery.log; then
        echo -n "export $(cat /tmp/sd-broker)" | tee /tmp/service-discovery
        echo | tee -a /tmp/service-discovery
    else
        echo "Broker service autodiscovery failed."
    fi
fi

if [[ -n $SD_ZOOKEEPER_FILTER ]]; then
    zk_jmx=""
    if [[ -n $SD_ZOOKEEPER_JMX_PORT ]]; then
        zk_jmx="-jmx-port $SD_ZOOKEEPER_JMX_PORT"
    fi
    if $FASTDATA_SD \
           -mode=zookeeper -port $SD_ZOOKEEPER_PORT $zk_jmx \
           addrs $SD_CONFIG \
           $SD_ZOOKEEPER_FILTER > /tmp/sd-zookeeper 2>>/tmp/service-discovery.log; then
        echo -n "export $(cat /tmp/sd-zookeeper)" | tee -a /tmp/service-discovery
        echo | tee -a /tmp/service-discovery
    else
        echo "Zookeeper service autodiscovery failed."
    fi
fi
