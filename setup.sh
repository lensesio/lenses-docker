#!/usr/bin/env bash

umask 0077

OPTS_JVM="LENSES_OPTS LENSES_HEAP_OPTS LENSES_JMX_OPTS LENSES_LOG4J_OPTS LENSES_PERFORMANCE_OPTS"
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
OPTS_SENSITIVE="LENSES_SECURITY_USERS LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD LICENSE LICENSE_URL LENSES_SECURITY_GROUPS"

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

# Run fastdata-sd
/usr/local/bin/service-discovery.sh
if [[ -f /tmp/service-discovery ]]; then
    source /tmp/service-discovery
fi

# Check for important settings that aren't explicitly set
[[ -z $LENSES_PORT ]] \
    && echo "LENSES_PORT=9991 is not set."

[[ -z $LENSES_KAFKA_BROKERS ]] \
    && echo "LENSES_KAFKA_BROKERS is not set."

[[ -z $LENSES_ZOOKEEPER_HOSTS ]] \
    && echo "LENSES_ZOOKEEPERS is not set."

[[ -z $LENSES_SCHEMA_REGISTRY_URLS ]]  \
    && echo "LENSES_SCHEMA_REGISTRY_URLS is not set."

[[ -z $LENSES_CONNECT_CLUSTERS ]] \
    && echo "LENSES_CONNECT_CLUSTERS is not set."

[[ -z $LENSES_SECURITY_USERS ]] \
    && echo "LENSES_SECURITY_USERS is not set."

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
    if [[ "${!var}" =~ .*[?:,()*/].* ]]; then
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
    chown -R nobody:nogroup /data/log /data/kafka-streams-state /data/license.json /data/lenses.conf /data/security.conf /data/logback.xml
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

exec $C_SUCMD $C_SUID /opt/lenses/bin/lenses /data/lenses.conf
