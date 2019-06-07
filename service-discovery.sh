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

SD_REGISTRY_FILTER=${SD_REGISTRY_FILTER:-}
SD_REGISTRY_PORT=${SD_REGISTRY_PORT:-8081}
SD_REGISTRY_JMX_PORT=${SD_REGISTRY_JMX_PORT:-}

# These are comma separated values
SD_CONNECT_FILTERS=${SD_CONNECT_FILTERS:-}
SD_CONNECT_NAMES=${SD_CONNECT_NAMES:-default}
SD_CONNECT_PORTS=${SD_CONNECT_PORTS:-8083}
SD_CONNECT_JMX_PORTS=${SD_CONNECT_JMX_PORTS:-}
SD_CONNECT_STATUSES=${SD_CONNECT_STATUSES:-connect-statuses}
SD_CONNECT_OFFSETS=${SD_CONNECT_OFFSETS:-connect-offsets}
SD_CONNECT_CONFIGS=${SD_CONNECT_CONFIGS:-connect-configs}

TRUE_REG='^([tT][rR][uU][eE]|[yY]|[yY][eE][sS]|1)$'
FALSE_REG='^([fF][aA][lL][sS][eE]|[nN]|[nN][oO]|0)$'

rm -f /tmp/sd-broker /tmp/sd-zookeeper /tmp/sd-registry /tmp/sd-connect-tmp /tmp/sd-connect /tmp/service-discovery /tmp/service-discovery.log

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

if [[ -n $SD_REGISTRY_FILTER ]]; then
    sr_jmx=""
    if [[ -n $SD_REGISTRY_JMX_PORT ]]; then
        sr_jmx="-jmx-port $SD_REGISTRY_JMX_PORT"
    fi
    if $FASTDATA_SD \
           -mode=registry -port $SD_REGISTRY_PORT $sr_jmx \
           addrs $SD_CONFIG \
           $SD_REGISTRY_FILTER > /tmp/sd-registry 2>>/tmp/service-discovery.log; then
        echo -n "export $(cat /tmp/sd-registry)" | tee -a /tmp/service-discovery
        echo | tee -a /tmp/service-discovery
    else
        echo "Schema registry service autodiscovery failed."
    fi
fi

if [[ -z $SD_CONNECT_FILTERS ]]; then
    exit 0
fi

IFS="," read -r -a c_filters <<< "$SD_CONNECT_FILTERS"
IFS="," read -r -a c_names <<< "$SD_CONNECT_NAMES"
IFS="," read -r -a c_ports <<< "$SD_CONNECT_PORTS"
IFS="," read -r -a c_jmx_ports <<< "$SD_CONNECT_JMX_PORTS"
IFS="," read -r -a c_statuses <<< "$SD_CONNECT_STATUSES"
IFS="," read -r -a c_configs <<< "$SD_CONNECT_CONFIGS"
IFS="," read -r -a c_offsets <<< "$SD_CONNECT_OFFSETS"

c_length=${#c_filters[@]}
c_port=""
c_jmx_port=""
function check_length(){
    # Connect ports can have length 1
    if [[ $2 == SD_CONNECT_PORTS ]]; then
        if ! [[ $SD_CONNECT_PORTS =~ .*,.* ]]; then
            c_port=$SD_CONNECT_PORTS
            return
        fi
        # Connect jmx ports can have lengths 0 and 1
    elif [[ $2 == SD_CONNECT_JMX_PORTS ]]; then
        if [[ -z $1 ]]; then return
        elif ! [[ $SD_CONNECT_JMX_PORTS =~ .*,.* ]]; then
            c_jmx_port=$SD_CONNECT_JMX_PORTS
            return
        fi
    fi
    if [[ $c_length != $1 ]]; then
        echo "DEBUG c_length: $c_length, 1: $1"

        echo "SD_CONNECT_FILTERS length different than $2 length."
        echo "Won't perform service discovery for connect."
        exit 0
    fi
}
# Check if all arrays have the same length. For ports we also accept length 1. For jmx_ports we also accept lengths 0 and 1.
check_length ${#c_names[@]} SD_CONNECT_NAMES
check_length ${#c_ports[@]} SD_CONNECT_PORTS
check_length ${#c_jmx_ports[@]} SD_CONNECT_JMX_PORTS
check_length ${#c_statuses[@]} SD_CONNECT_STATUSES
check_length ${#c_configs[@]} SD_CONNECT_CONFIGS
check_length ${#c_offsets[@]} SD_CONNECT_OFFSETS
cp_length=${c_ports[@]}
cjp_length=${c_jmx_ports[@]}
for index in "${!c_filters[@]}"; do
    c_port_final=""
    c_jmx_port_final=""
    if [[ -z $c_port ]]; then
        c_port_final="${c_ports[index]}"
    else
        c_port_final=$c_port
    fi
    if [[ -n $c_jmx_port ]]; then
        c_jmx_port_final="-jmx-port $c_jmx_port"
    elif ! [[ -z $SD_CONNECT_JMX_PORTS ]]; then
            c_jmx_port_final="-jmx-port ${c_jmx_ports[index]}"
    fi
    echo $FASTDATA_SD \
           -mode=connect -port $c_port_final $c_jmx_port_final \
           -cluster-name ${c_names[index]} -statuses ${c_statuses[index]} -configs ${c_configs[index]} -offsets ${c_offsets[index]} \
           addrs $SD_CONFIG \
           ${c_filters[index]}
    if $FASTDATA_SD \
           -mode=connect -port $c_port_final $c_jmx_port_final \
           -cluster-name ${c_names[index]} -statuses ${c_statuses[index]} -configs ${c_configs[index]} -offsets ${c_offsets[index]} \
           addrs $SD_CONFIG \
           ${c_filters[index]} > /tmp/sd-connect-tmp 2>>/tmp/service-discovery.log; then
        cat /tmp/sd-connect-tmp >> /tmp/sd-connect
        echo -n "," >> /tmp/sd-connect
    else
        echo "Connect '${c_names[index]}' service autodiscovery failed."
    fi
done
if [[ -f /tmp/sd-connect ]]; then
    echo "export LENSES_KAFKA_CONNECT_CLUSTERS='[$(cat /tmp/sd-connect | sed -e 's/,$//')]'" | tee -a /tmp/service-discovery
    echo
fi

