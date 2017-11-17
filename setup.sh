#!/usr/bin/env bash

umask 0077

OPTS_JVM="LENSES_OPTS LENSES_HEAP_OPTS LENSES_JMX_OPTS LENSES_LOG4J_OPTS LENSES_PERFORMANCE_OPTS"
OPTS_NEEDQUOTE="LENSES_LICENSE_FILE LENSES_KAFKA_BROKERS LENSES_ZOOKEEPER_HOSTS LENSES_SCHEMA_REGISTRY_URLS LENSES_GRAFANA"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_JMX_BROKERS LENSES_JMX_SCHEMA_REGISTRY LENSES_JMX_ZOOKEEPERS"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_ACCESS_CONTROL_ALLOW_METHODS LENSES_ACCESS_CONTROL_ALLOW_ORIGIN LENSES_VERSION"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_LDAP_URL LENSES_SECURITY_LDAP_BASE LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_LDAP_LOGIN_FILTER LENSES_SECURITY_LDAP_MEMBEROF_KEY LENSES_SECURITY_MEMBEROF_KEY"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_LDAP_GROUP_EXTRACT_REGEX"
# We started with expicit setting conf options that need quoting (OPTS_NEEDQUOTE) but k8s (and docker linking) can create settings
# that we process (env var that starts with 'LENSES_') and put into the conf file. Although lenses will ignore the settings,
# these settings usually include characters that need quotes, that now we also set explicitly which fields do not need
# quotes. Later for settings that do not much either of OPTS_NEEDQUOTE and OPTS_NEEDNOQUOTE we try to autodetect if quotes are needed.
OPTS_NEEDNOQUOTE="LENSES_CONNECT LENSES_JMX_CONNECT LENSES_SECURITY_USERS LENSES_UI_CONFIG_DISPLAY LENSES_KAFKA_TOPICS"
OPTS_SENSITIVE="LENSES_SECURITY_USERS LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD LICENSE LICENSE_URL"

# Load settings from files
for fileSetting in $(find /mnt/settings -name "LENSES_*"); do
    fileSettingClean="$(basename "$fileSetting")"
    export "${fileSettingClean}"="$(cat "$fileSetting")"
    echo "$fileSetting"
done

# Load secrets from files
for fileSecret in $(find /mnt/secrets -name "LENSES_*"); do
    fileSecretClean="$(basename "$fileSecret")"
    export "${fileSecretClean}"="$(cat "$fileSecret")"
    echo "$fileSecret"
done

# Check for important settings that aren't explicitly set
[[ -z $LENSES_PORT ]] && export LENSES_PORT='9991' \
    && echo "Setting LENSES_PORT=9991. Override by setting the environment variable."

[[ -z $LENSES_KAFKA_BROKERS ]] && export LENSES_KAFKA_BROKERS='PLAINTEXT://localhost:9092' \
    && echo "Setting LENSES_KAFKA_BROKERS='PLAINTEXT://localhost:9092'. Override by setting the environment variable."

[[ -z $LENSES_ZOOKEEPER_HOSTS ]] && export LENSES_ZOOKEEPER_HOSTS='localhost:2181' \
    && echo "Setting LENSES_ZOOKEEPERS='localhost:2181'. Override by setting the environment variable."

[[ -z $LENSES_SCHEMA_REGISTRY_URLS ]]  && export LENSES_SCHEMA_REGISTRY_URLS='http://localhost:8081' \
    && echo "Setting LENSES_SCHEMA_REGISTRY_URLS='http://localhost:8081'. Override by setting the environment variable."

[[ -z $LENSES_CONNECT ]] && export LENSES_CONNECT='[{default:"http://localhost:8083"}]' \
    && echo "Setting LENSES_CONNECT='[{default:\"http://localhost:8083\"}]'. Override by setting the environment variable."

[[ -z $LENSES_JMX_BROKERS ]] \
    && echo "LENSES_JMX_BROKERS is not set. Some functionality won't be available."

[[ -z $LENSES_JMX_SCHEMA_REGISTRY ]] \
    && echo "LENSES_JMX_SCHEMA_REGISTRY is not set. Some functionality won't be available."

[[ -z $LENSES_JMX_ZOOKEEPERS ]] \
    && echo "LENSES_JMX_ZOOKEEPERS is not set. Some functionality won't be available."

[[ -z $LENSES_JMX_CONNECT ]] \
    && echo "LENSES_JMX_CONNECT is not set. Some functionality won't be available."

[[ -z $LENSES_SECURITY_USERS ]] \
    && export LENSES_SECURITY_USERS='[{"username": "admin", "password": "admin", "displayname": "Lenses Admin", "roles": ["admin", "write", "read"]}]' \
    && echo "LENSES_SECURITY_USERS is not set. Setting default user 'admin' with password 'admin'."

[[ -z $LENSES_SQL_STATE_DIR ]] && export LENSES_SQL_STATE_DIR=/data/kafka-streams-state

# Set logging
sed -e 's|>logs/|>/data/log/|g' /opt/lenses/logback.xml > /data/logback.xml
[[ -z "$LENSES_LOG4J_OPTS" ]] && export LENSES_LOG4J_OPTS="-Dlogback.configurationFile=file:/data/logback.xml"

# Check for port availability
if ! /usr/local/bin/checkport -port "$LENSES_PORT"; then
    echo "ERROR! Lenses port (LENSES_PORT=$LENSES_PORT) is in use by some other program."
    echo "       Lenses will probably fail to start."
fi

# Add prefix and suffix spaces, so our regexp check below will work.
OPTS_JVM=" $OPTS_JVM "
OPTS_NEEDQUOTE=" $OPTS_NEEDQUOTE "
OPTS_NEEDNOQUOTE=" $OPTS_NEEDNOQUOTE "
OPTS_SENSITIVE=" $OPTS_SENSITIVE "

# Remove configuration because it will be re-created.
rm -f /data/lenses.conf
rm -rf /tmp/vlxjre

# Rename env vars and write settings or export OPTS
for var in $(printenv | grep -E "^LENSES_" | sed -e 's/=.*//'); do
    # Try to detect some envs set by kubernetes and/or docker link and skip them.
    if [[ "$var" =~ [^=]+TCP_(PORT|ADDR).* ]] \
           || [[ "$var" =~ [^=]+_[0-9]{1,5}_(TCP|UDP).* ]] \
           || [[ "$var" =~ [^=]+_SERVICE_PORT.* ]]; then
        echo "Skipping variable probably set by container supervisor: $var"
        continue
    fi

    # If _OPTS, export them
    if [[ "$OPTS_JVM" =~ " $var " ]]; then
        export "${var}"="${!var}"
        continue
    fi

    # Convert var name to lowercase
    conf="${var,,}"
    # Convert underscores in var name to stops
    conf="${conf//_/.}"

    # If setting needs to be quoted, write with quotes
    if [[ "$OPTS_NEEDQUOTE" =~ " $var " ]]; then
        echo "${conf}=\"${!var}\"" >> /data/lenses.conf
        if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=\"${!var}\""
        fi
        continue
    fi

    # If settings must not have quotes, write without quotes
    if [[ "$OPTS_NEEDNOQUOTE" =~ " $var " ]]; then
        echo "${conf}=${!var}" >> /data/lenses.conf
        if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=${!var}"
        fi
        continue
    fi

    # Else try to detect if we need quotes
    if [[ "${!var}" =~ [^=]+=.*[?:,*/].* ]]; then
        echo -n "[Variable needed quotes] "
        echo "${conf}=\"${!var}\"" >> /data/lenses.conf
    else
        echo "${conf}=${!var}" >> /data/lenses.conf
    fi
    if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
        echo "${conf}=********"
        unset "${var}"
    else
        echo "${conf}=${!var}"
    fi
done

# Fix for case sensitive LDAP setting:
sed -r -e 's/^lenses\.security\.ldap\.memberof\.key=/lenses.security.ldap.memberOf.key=/' -i /data/lenses.conf

# If not explicit license path
if ! grep -sq 'lenses.license.file=' /data/lenses.conf; then
    echo "lenses.license.file=/data/license.json" >> /data/lenses.conf
# Take care of  license path
    if [[ -f /license.json ]]; then
        cp /license.json /data/license.json
    elif [[ -f /mnt/secrets/license.json ]]; then
        cp /mnt/secrets/license.json /data/license.json
    elif [[ ! -z "$LICENSE" ]] && [[ ! -f /data/license.json ]]; then
        echo "$LICENSE" >> /data/license.json
    elif [[ ! -z "$LICENSE_URL" ]] && [[ ! -f /data/license.json ]]; then
        wget "$LICENSE_URL" -O /data/license.json
        if [[ $? -ne 0 ]]; then
            echo "ERROR! Could not download license. Maybe the link was wrong or the license expired?"
            echo "       Please check and try again. If the problem persists contact Landoop."
            exit 1
        fi
    elif [[ -f /data/license.json ]]; then
        echo
    else
        echo -e "ERROR! No license was provided. Lenses will not work."
    fi
fi

# We created all need files. Set a more permissive umask for data and logs
umask 0027

# Check User and Group IDs
C_UID="$(id -u)"
C_GID="$(id -g)"
# C_LOG_UID="$(stat -c '%u' /data/log)"
# C_LOG_GID="$(stat -c '%g' /data/log)"
# C_STATE_UID="$(stat -c '%u' /data/kafka-streams-state)"
# C_STATE_GID="$(stat -c '%g' /data/kafka-streams-state)"
C_SUCMD=""
C_SUID=""
if [[ "$C_UID" == 0 ]]; then
    echo "Running as root. Will change data ownership to nobody:nogroup (65534:65534)"
    echo "and drop priviliges."
    chown -R nobody:nogroup /data/log /data/kafka-streams-state /data/license.json /data/lenses.conf /data/logback.xml
    C_SUCMD=/usr/sbin/gosu
    C_SUID="nobody:nogroup"
else
    LOG_WRITEABLE=0
    STATE_WRITEABLE=0
    echo "Running as user:group $C_UID:$C_GID. Checking permissions."
    touch /data/log/lenses-test >/dev/null 2>&1 \
        && LOG_WRITEABLE=1 && rm /data/log/lenses-test
    [[ $LOG_WRITEABLE == 0 ]] \
        && echo "ERROR! /data/log/ is not writeable by the set user:group ($C_UID:$C_GID)." \
        && echo "       You can ignore this error if you set a custom, writeable directory for logs."
    touch /data/kafka-streams-state/lenses-test >/dev/null 2>&1 \
        && STATE_WRITEABLE=1 && rm /data/kafka-streams-state/lenses-test
    [[ $STATE_WRITEABLE == 0 ]] \
        && echo "ERROR! /data/kafka-streams-state/ is not writeable by the set user:group ($C_UID:$C_GID)." \
        && echo "       You can ignore this error if you set a custom, writeable directory for state."
fi

exec $C_SUCMD $C_SUID /opt/lenses/bin/lenses /data/lenses.conf
