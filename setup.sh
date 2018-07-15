#!/usr/bin/env bash

umask 0077

TRUE_REG='^([tT][rR][uU][eE]|[yY]|[yY][eE][sS]|1)$'
FALSE_REG='^([fF][aA][lL][sS][eE]|[nN]|[nN][oO]|0)$'

DEBUG_SCRIPT=${DEBUG_SCRIPT:-false}
if [[ $DEBUG_SCRIPT =~ $TRUE_REG ]]; then
    set -o xtrace
fi

STRICT_SCRIPT=${STRICT_SCRIPT:-false}
if [[ $STRICT_SCRIPT =~ $FALSE_REG ]]; then
    set +o errexit
    set +o nounset
    set +o pipefail
fi

PAUSE_EXEC=${PAUSE_EXEC:-false}

OPTS_JVM="LENSES_OPTS LENSES_HEAP_OPTS LENSES_JMX_OPTS LENSES_LOG4J_OPTS LENSES_PERFORMANCE_OPTS LENSES_SERDE_CLASSPATH_OPTS"
OPTS_NEEDQUOTE="LENSES_LICENSE_FILE LENSES_KAFKA_BROKERS"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_GRAFANA LENSES_JMX_BROKERS LENSES_JMX_SCHEMA_REGISTRY LENSES_JMX_ZOOKEEPERS"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_ACCESS_CONTROL_ALLOW_METHODS LENSES_ACCESS_CONTROL_ALLOW_ORIGIN"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_VERSION LENSES_SECURITY_LDAP_URL LENSES_SECURITY_LDAP_BASE"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_LDAP_LOGIN_FILTER LENSES_SECURITY_LDAP_MEMBEROF_KEY"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_SECURITY_MEMBEROF_KEY LENSES_SECURITY_LDAP_GROUP_EXTRACT_REGEX"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_TOPICS_ALERTS_STORAGE LENSES_ZOOKEEPER_CHROOT LENSES_ALERT_MANAGER_ENDPOINTS LENSES_ALERT_MANAGER_SOURCE"
# We started with expicit setting conf options that need quoting (OPTS_NEEDQUOTE) but k8s (and docker linking)
# can create settings that we process (env vars that start with 'LENSES_') and put into the conf file. Although
# lenses will ignore these settings, they usually include characters that need quotes, so now we also need to
# set explicitly which fields do not need quotes. For the settings that do not much either of OPTS_NEEDQUOTE
# or OPTS_NEEDNOQUOTE we try to autodetect if quotes are needed.
OPTS_NEEDNOQUOTE="LENSES_CONNECT LENSES_CONNECT_CLUSTERS LENSES_JMX_CONNECT LENSES_SECURITY_USERS"
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_UI_CONFIG_DISPLAY LENSES_KAFKA_TOPICS LENSES_SQL_CONNECT_CLUSTERS"
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_ZOOKEEPER_HOSTS LENSES_SCHEMA_REGISTRY_URLS LENSES_SECURITY_GROUPS"
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_SECURITY_SERVICE_ACCOUNTS"
OPTS_SENSITIVE="LENSES_SECURITY_USERS LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD LICENSE LICENSE_URL"
OPTS_SENSITIVE="$OPTS_SENSITIVE LENSES_SECURITY_GROUPS LENSES_SECURITY_SERVICE_ACCOUNTS"
OPTS_SENSITIVE="$OPTS_SENSITIVE LENSES_KAFKA_SETTINGS_CONSUMER_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_CONSUMER_SSL_KEY_PASSWORD LENSES_KAFKA_SETTINGS_CONSUMER_SSL_TRUSTSTORE_PASSWORD"
OPTS_SENSITIVE="$OPTS_SENSITIVE LENSES_KAFKA_SETTINGS_PRODUCER_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_PRODUCER_SSL_KEY_PASSWORD LENSES_KAFKA_SETTINGS_PRODUCER_SSL_TRUSTSTORE_PASSWORD"

# LOAD settings from files
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
# Docker Swarm (older versions) only export to /run/secrets
if [[ -d /run/secrets ]]; then
    for fileSecret in $(find /mnt/secrets -name "LENSES_*"); do
        fileSecretClean="$(basename "$fileSecret")"
        export "${fileSecretClean}"="$(cat "$fileSecret")"
        echo "$fileSecret"
    done
fi

# Run fastdata-sd
/usr/local/bin/service-discovery.sh
if [[ -f /tmp/service-discovery ]]; then
    source /tmp/service-discovery
fi

# Check for important settings that aren't explicitly set
[[ -z $LENSES_PORT ]] \
    && echo "LENSES_PORT is not set via env var or individual file."

[[ -z $LENSES_KAFKA_BROKERS ]] \
    && echo "LENSES_KAFKA_BROKERS is not set via env var or individual file."

[[ -z $LENSES_ZOOKEEPER_HOSTS ]] \
    && echo "LENSES_ZOOKEEPERS is not set via env var or individual file."

[[ -z $LENSES_SCHEMA_REGISTRY_URLS ]]  \
    && echo "LENSES_SCHEMA_REGISTRY_URLS is not set via env var or individual file."

[[ -z $LENSES_CONNECT_CLUSTERS ]] \
    && echo "LENSES_CONNECT_CLUSTERS is not set via env var or individual file."

[[ -z $LENSES_SECURITY_USERS ]] \
    && echo "LENSES_SECURITY_USERS is not set via env var or individual file."

if [[ -z $LENSES_SQL_STATE_DIR ]]; then
    if [[ -z $LENSES_SQL_EXECUTION_MODE ]] || [[ $LENSES_SQL_EXECUTION_MODE == IN_PROC ]]; then
        export LENSES_SQL_STATE_DIR=/data/kafka-streams-state
    elif [[ $LENSES_SQL_EXECUTION_MODE == CONNECT ]]; then
        export LENSES_SQL_STATE_DIR=/tmp/lenses-kafka-streams-state
    fi
fi

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

# This takes as arguments a variable name and a file (lenses.conf or security.conf)
# and process the variable before adding it to the file (i.e convert to lowercase,
# check if it needs quotes, etc).
function process_variable {
    local var="$1"
    local config_file="$2"

    # Convert var name to lowercase
    conf="${var,,}"
    # Convert underscores in var name to stops
    conf="${conf//_/.}"

    # If setting needs to be quoted, write with quotes
    if [[ "$OPTS_NEEDQUOTE" =~ " $var " ]]; then
        echo "${conf}=\"${!var}\"" >> "$config_file"
        if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=\"${!var}\""
        fi
        return 0
    fi

    # If settings must not have quotes, write without quotes
    if [[ "$OPTS_NEEDNOQUOTE" =~ " $var " ]]; then
        echo "${conf}=${!var}" >> "$config_file"
        if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=${!var}"
        fi
        return 0
    fi

    # Else try to detect if we need quotes
    if [[ "${!var}" =~ .*[?:,()*/|].* ]]; then
        echo -n "[Variable needed quotes] "
        echo "${conf}=\"${!var}\"" >> "$config_file"
    else
        echo "${conf}=${!var}" >> "$config_file"
    fi
    if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
        echo "${conf}=********"
        unset "${var}"
    else
        echo "${conf}=${!var}"
    fi
}

DETECTED_LENFILE=false
if [[ -f /mnt/settings/lenses.conf ]]; then
    echo "Detected /mnt/settings/lenses.conf. Will use that and ignore any environment variables!"
    cp /mnt/settings/lenses.conf /data/lenses.conf
    DETECTED_LENFILE=true
fi

DETECTED_SECFILE=false
if [[ -f /mnt/secrets/security.conf ]]; then
    echo "Detected /mnt/secrets/security.conf. Will use that and ignore any environment variables!"
    cp /mnt/secrets/security.conf /data/security.conf
    DETECTED_SECFILE=true
fi

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

    if [[ "$var" =~ ^LENSES_SECURITY.* ]]; then
        if [[ "$DETECTED_SECFILE" == "false" ]]; then
            process_variable "$var" /data/security.conf
        fi
    else
        if [[ "$DETECTED_LENFILE" == "false" ]]; then
            process_variable "$var" /data/lenses.conf
        fi
    fi
done

# Find side files (SSL trust/key stores, jaas, krb5) shared via
# mounts/secrets and load them as temp env vars
BASE64_REGEXP="^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
# Mounts
for fileSetting in $(find /mnt/settings -name "FILE_*"); do
    ENCODE=cat
    if cat "$fileSetting" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
        ENCODE="base64"
    fi
    fileSettingClean="$(basename "$fileSetting")"
    export "${fileSettingClean}"="$($ENCODE "$fileSetting")"
    echo "Found $fileSetting"
done
# Secret mounts
for fileSecret in $(find /mnt/secrets -name "FILE_*"); do
    ENCODE=cat
    if cat "$fileSecret" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
        ENCODE="base64"
    fi
    fileSecretClean="$(basename "$fileSecret")"
    export "${fileSecretClean}"="$($ENCODE "$fileSecret")"
    echo "Found $fileSecret"
done
# Docker Swarm (older versions) only export to /run/secrets
if [[ -d /run/secrets ]]; then
    for fileSecret in $(find /mnt/secrets -name "FILE_*"); do
        ENCODE=cat
        if cat "$fileSecret" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
            ENCODE="base64"
        fi
        fileSecretClean="$(basename "$fileSecret")"
        export "${fileSecretClean}"="$($ENCODE "$fileSecret")"
        echo "Found $fileSecret"
    done
fi
# Process them
for var in $(printenv | grep -E "^FILE_" | sed -e 's/=.*//'); do
    case "$var" in
        FILE_SSL_KEYSTORE)
            if [[ -n $FILE_SSL_KEYSTORE ]]; then
                DECODE="cat"
                if ! echo -n "$FILE_SSL_KEYSTORE" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
                    DECODE="base64 -d"
                fi
                $DECODE <<< "$FILE_SSL_KEYSTORE" > /data/keystore.jks
                chmod 400 /data/keystore.jks
                echo "lenses.kafka.settings.consumer.ssl.keystore.location=/data/keystore.jks" >> /data/lenses.conf
                echo "lenses.kafka.settings.producer.ssl.keystore.location=/data/keystore.jks" >> /data/lenses.conf
                echo "File created. Sha256sum: $(sha256sum /data/keystore.jks)"
                unset FILE_SSL_KEYSTORE
            fi
            ;;
        FILE_SSL_TRUSTSTORE)
            if [[ -n $FILE_SSL_TRUSTSTORE ]]; then
                DECODE="cat"
                if ! echo -n "$FILE_SSL_TRUSTSTORE" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
                    DECODE="base64 -d"
                fi
                $DECODE <<< "$FILE_SSL_TRUSTSTORE" > /data/truststore.jks
                chmod 400 /data/truststore.jks
                echo "lenses.kafka.settings.consumer.ssl.truststore.location=/data/truststore.jks" >> /data/lenses.conf
                echo "lenses.kafka.settings.producer.ssl.truststore.location=/data/truststore.jks" >> /data/lenses.conf
                echo "File created. Sha256sum: $(sha256sum /data/truststore.jks)"
                unset FILE_SSL_TRUSTSTORE
            fi
            ;;
        FILE_JAAS)
            if [[ -n $FILE_JAAS ]]; then
                DECODE="cat"
                if ! echo -n "$FILE_JAAS" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
                    DECODE="base64 -d"
                fi
                $DECODE <<< "$FILE_JAAS" > /data/jaas.conf
                chmod 400 /data/jaas.conf
                export LENSES_OPTS="$LENSES_OPTS -Djava.security.auth.login.config=/data/jaas.conf"
                echo "File created. Sha256sum: $(sha256sum /data/jaas.conf)"
                unset FILE_JAAS
            fi
            ;;
        FILE_KRB5)
            if [[ -n $FILE_KRB5 ]]; then
                DECODE="cat"
                if ! echo -n "$FILE_KRB5" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
                    DECODE="base64 -d"
                fi
                $DECODE <<< "$FILE_KRB5" > /data/krb5.conf
                chmod 400 /data/krb5.conf
                export LENSES_OPTS="$LENSES_OPTS -Djava.security.krb5.conf=/data/krb5.conf"
                echo "File created. Sha256sum: $(sha256sum /data/krb5.conf)"
                unset FILE_KRB5
            fi
            ;;
        *)
            echo "Unknown file variable $var was provided but won't be used."
            ;;
    esac
done

# # Fix for case sensitive LDAP setting:
# sed -r -e 's/^lenses\.security\.ldap\.memberof\.key=/lenses.security.ldap.memberOf.key=/' -i /data/lenses.conf

# If not explicit security file set auto-generated:
DETECTED_SECAPPENDFILE=false
if ! grep -sqE '^lenses.secret.file=' /data/lenses.conf; then
    echo -e "\nlenses.secret.file=/data/security.conf" >> /data/lenses.conf
else
    DETECTED_SECAPPENDFILE=true
fi

# If not explicit license path
if ! grep -sqE '^lenses.license.file=' /data/lenses.conf; then
    echo -e "\nlenses.license.file=/data/license.json" >> /data/lenses.conf
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

# Append Advanced Configuration Snippet
if [[ -f /mnt/settings/lenses.append.conf ]]; then
    cat /mnt/settings/lenses.append.conf >> /data/lenses.conf
    echo "Appending advanced configuration snippet to lenses.conf"
fi
if [[ -f /mnt/settings/security.append.conf ]]; then
    cat /mnt/settings/security.append.conf >> /data/security.conf
    echo "Appending advanced configuration snippet to security.conf."
    if [[ $DETECTED_SECAPPENDFILE == true ]]; then
        echo "WARN: advanced configuration snippet may fail to be applied to user provided security.conf file."
    fi
fi

# Clear empty values (just in case)
sed '/^\s*[^=]*=\s*$/d' -i /data/lenses.conf /data/security.conf

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
    chown -R -f nobody:nogroup \
          /data/log \
          /data/kafka-streams-state \
          /data/license.json \
          /data/lenses.conf \
          /data/security.conf \
          /data/logback.xml \
          /data/keystore.jks \
          /data/truststore.jks \
          /data/jaas.conf \
          /data/krb5.conf
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

# Enable fastdata_agent for exporting metrics to prometheus
export LENSES_OPTS="$LENSES_OPTS -javaagent:/opt/landoop/fast_data_monitoring/fastdata_agent.jar=9102:opt/landoop/fast_data_monitoring/client.yml"

# If PAUSE_EXEC is set, we wait for 10 minutes before starting lenses.
# This way we can go into the container and debug things before it exits.
if [[ $PAUSE_EXEC =~ $TRUE_REG ]]; then
    sleep 600
fi

exec $C_SUCMD $C_SUID /opt/lenses/bin/lenses /data/lenses.conf
