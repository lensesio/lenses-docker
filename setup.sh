#!/usr/bin/env bash

echo "Initializing environment —docker setup script."

umask 0077

TRUE_REG='^([tT][rR][uU][eE]|[yY]|[yY][eE][sS]|1)$'
FALSE_REG='^([fF][aA][lL][sS][eE]|[nN]|[nN][oO]|0)$'

DEBUG_SCRIPT=${DEBUG_SCRIPT:-false}
if [[ $DEBUG_SCRIPT =~ $TRUE_REG ]]; then
    set -o xtrace
fi

STRICT_SCRIPT=${STRICT_SCRIPT:-false}
if [[ $STRICT_SCRIPT =~ $TRUE_REG ]]; then
    set -o errexit
    set -o nounset
    set -o pipefail
fi

source /build.info
export LT_PACKAGE=${LT_PACKAGE:-docker}
export LT_PACKAGE_VERSION=${LT_PACKAGE_VERSION:-$BUILD_COMMIT}

export PROMETHEUS_METRICS_PORT=${PROMETHEUS_METRICS_PORT:-9102}
DEBUG_TOOLS=${DEBUG_TOOLS:-false}

WAIT_SCRIPT=${WAIT_SCRIPT:-}
OLD_QUOTING=${OLD_QUOTING:-0}

OPTS_JVM="LENSES_OPTS LENSES_HEAP_OPTS LENSES_JMX_OPTS LENSES_LOG4J_OPTS LENSES_PERFORMANCE_OPTS LENSES_SERDE_CLASSPATH_OPTS LENSES_PLUGINS_CLASSPATH_OPTS LENSES_APPEND_CONF"
OPTS_JVM="$OPTS_JVM LENSES_AGENT_APPEND_CONF SECURITY_APPEND_CONF"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_GRAFANA"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_ACCESS_CONTROL_ALLOW_METHODS LENSES_ACCESS_CONTROL_ALLOW_ORIGIN"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_VERSION"
OPTS_NEEDQUOTE="$OPTS_NEEDQUOTE LENSES_STORAGE_POSTGRES_PASSWORD"
# Deprecated settings. We keep them to avoid breaking Lenses for people who forget to remove them.
OPTS_NEEDQUOTE_DEPR="LENSES_ALERT_MANAGER_SOURCE LENSES_ALERT_MANAGER_ENDPOINTS"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_ALERTING_PLUGIN_CONFIG_ICON_URL"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_TOPICS_ALERTS_STORAGE LENSES_ZOOKEEPER_CHROOT LENSES_JMX_ZOOKEEPERS"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_LDAP_URL LENSES_SECURITY_LDAP_BASE"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_USER LENSES_SECURITY_PASSWORD"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_LDAP_LOGIN_FILTER LENSES_SECURITY_LDAP_MEMBEROF_KEY"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_MEMBEROF_KEY LENSES_SECURITY_LDAP_GROUP_EXTRACT_REGEX"
OPTS_NEEDQUOTE_DEPR="$OPTS_NEEDQUOTE_DEPR LENSES_SECURITY_BASIC_PASSWORD_RULES_REGEX LENSES_SECURITY_BASIC_PASSWORD_RULES_DESC"

# We started with expicit setting conf options that need quoting (OPTS_NEEDQUOTE) but k8s (and docker linking)
# can create settings that we process (env vars that start with 'LENSES_') and put into the conf file. Although
# lenses will ignore these settings, they usually include characters that need quotes, so now we also need to
# set explicitly which fields do not need quotes. For the settings that do not much either of OPTS_NEEDQUOTE
# or OPTS_NEEDNOQUOTE we try to autodetect if quotes are needed.
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_SQL_UDF_PACKAGES LENSES_UI_CONFIG_DISPLAY LENSES_KAFKA_TOPICS"
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_KUBERNETES_NAMESPACES LENSES_KUBERNETES_NAMESPACES_INCLUSTER"
OPTS_NEEDNOQUOTE="$OPTS_NEEDNOQUOTE LENSES_KAFKA_CONTROL_TOPICS LENSES_CONNECTORS_INFO"
# Deprecated settings. We keep them to avoid breaking Lenses for people who forget to remove them.
OPTS_NEEDNOQUOTE_DEPR="LENSES_CONNECT LENSES_JMX_CONNECT LENSES_ALERT_PLUGINS"
OPTS_NEEDNOQUOTE_DEPR="$OPTS_NEEDNOQUOTE_DEPR LENSES_SQL_CONNECT_CLUSTERS LENSES_ZOOKEEPER_HOSTS"
OPTS_NEEDNOQUOTE_DEPR="$OPTS_NEEDNOQUOTE_DEPR LENSES_KAFKA LENSES_KAFKA_METRICS LENSES_KAFKA LENSES_KAFKA_METRICS"
OPTS_NEEDNOQUOTE_DEPR="$OPTS_NEEDNOQUOTE_DEPR LENSES_KAFKA_METRICS_PORT LENSES_SECURITY_USERS"
OPTS_NEEDNOQUOTE_DEPR="$OPTS_NEEDNOQUOTE_DEPR LENSES_SECURITY_GROUPS LENSES_SECURITY_SERVICE_ACCOUNTS LENSES_SECURITY_MAPPINGS"

# Some variables should be literals. Like all jaas settings which though we autodetect
OPTS_LITERAL=""
# Deprecated literals
OPTS_LITERAL_DEPR="LENSES_KAFKA_SETTINGS_PRODUCER_SASL_JAAS_CONFIG LENSES_KAFKA_SETTINGS_CONSUMER_SASL_JAAS_CONFIG"
OPTS_LITERAL_DEPR="$OPTS_LITERAL_DEPR LENSES_KUBERNETES_PROCESSOR_KAFKA_SETTINGS_SASL_JAAS_CONFIG LENSES_KUBERNETES_PROCESSOR_JAAS"
OPTS_LITERAL_DEPR="$OPTS_LITERAL_DEPR LENSES_KAFKA_SETTINGS_CLIENT_SASL_JAAS_CONFIG"

# Some variables are sensitive and should not be printed
OPTS_SENSITIVE="LENSES_STORAGE_POSTGRES_PASSWORD"
# These are deprecated but keep them so we protect users from suboptimal upgrades.
OPTS_SENSITIVE_DEPR="LENSES_SECURITY_USERS LENSES_SECURITY_GROUPS LENSES_SECURITY_SERVICE_ACCOUNTS"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_CONSUMER_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_CONSUMER_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_CONSUMER_SSL_TRUSTSTORE_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_PRODUCER_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_PRODUCER_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_PRODUCER_SSL_TRUSTSTORE_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_KSTREAM_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_KSTREAM_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_KSTREAM_SSL_TRUSTSTORE_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_PRODUCER_BASIC_AUTH_USER_INFO LENSES_SCHEMA_REGISTRY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_CONSUMER_BASIC_AUTH_USER_INFO LENSES_KUBERNETES_PROCESSOR_KAFKA_SETTINGS_BASIC_AUTH_USER_INFO"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KUBERNETES_PROCESSOR_SCHEMA_REGISTRY_SETTINGS_BASIC_AUTH_USER_INFO LENSES_KAFKA_METRICS_USER LENSES_KAFKA_METRICS_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_ALERTING_PLUGIN_CONFIG_WEBHOOK_URL LENSES_ALERTING_PLUGIN_CONFIG_USERNAME"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_CLIENT_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_SETTINGS_CLIENT_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_SETTINGS_CLIENT_SSL_TRUSTSTORE_PASSWORD LENSES_KAFKA_SETTINGS_CLIENT_BASIC_AUTH_USER_INFO"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_KAFKA_CONNECT_SSL_TRUSTSTORE_PASSWORD LENSES_KAFKA_CONNECT_SSL_KEYSTORE_PASSWORD LENSES_KAFKA_CONNECT_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_SECURITY_USER LENSES_SECURITY_PASSWORD LENSES_SECURITY_LDAP_USER LENSES_SECURITY_LDAP_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_SECURITY_SAML_KEY_PASSWORD LENSES_SECURITY_SAML_KEYSTORE_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_SECURITY_JWT_HMAC_SECRET_KEY"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_SSL_KEYSTORE_PASSWORD LENSES_SSL_KEY_PASSWORD"
OPTS_SENSITIVE_DEPR="$OPTS_SENSITIVE_DEPR LENSES_HQ_AGENT_KEY"

# LOAD settings from files
# This loop is fragile but we demand filenames that map to env vars anyway
# shellcheck disable=SC2044
for fileSetting in $(find /mnt/settings -name "LENSES_*"); do
    fileSettingClean="$(basename "$fileSetting")"
    export "${fileSettingClean}"="$(cat "$fileSetting")"
    echo "$fileSetting"
done

# Load secrets from files
# This loop is fragile but we demand filenames that map to env vars anyway
# shellcheck disable=SC2044
for fileSecret in $(find /mnt/secrets -name "LENSES_*"); do
    fileSecretClean="$(basename "$fileSecret")"
    export "${fileSecretClean}"="$(cat "$fileSecret")"
    echo "$fileSecret"
done
# Docker Swarm (older versions) only export to /run/secrets
if [[ -d /run/secrets ]]; then
    # This loop is fragile but we demand filenames that map to env vars anyway
    # shellcheck disable=SC2044
    for fileSecret in $(find /mnt/secrets -name "LENSES_*"); do
        fileSecretClean="$(basename "$fileSecret")"
        export "${fileSecretClean}"="$(cat "$fileSecret")"
        echo "$fileSecret"
    done
fi

# Set LENSES_PROVISIONING_PATH if not already set to point to autogenerated provisioning.yaml
export LENSES_PROVISIONING_PATH="${LENSES_PROVISIONING_PATH:-/data/provisioning}"

# If 'lenses.sql.state.dir' is not explicitly set, set it automatically
if [[ -z $LENSES_SQL_STATE_DIR ]]; then
    if [[ -z $LENSES_SQL_EXECUTION_MODE ]] || [[ $LENSES_SQL_EXECUTION_MODE == IN_PROC ]]; then
        export LENSES_SQL_STATE_DIR=/data/kafka-streams-state
    elif [[ $LENSES_SQL_EXECUTION_MODE == CONNECT ]]; then
        export LENSES_SQL_STATE_DIR=/tmp/lenses-kafka-streams-state
    fi
fi

# Set logging
if [[ ! -f /data/logback.xml ]]; then
    sed -e 's|>logs/|>/data/log/|g' /opt/lenses-agent/logback.xml > /data/logback.xml
fi

# Set plugins directory if not explicitly set
export LENSES_PLUGINS_CLASSPATH_OPTS=${LENSES_PLUGINS_CLASSPATH_OPTS:-/data/plugins}

# Add prefix and suffix spaces, so our regexp check below will work. Also add deprecated settings.
OPTS_JVM=" $OPTS_JVM "
OPTS_NEEDQUOTE=" $OPTS_NEEDQUOTE $OPTS_NEEDQUOTE_DEPR "
OPTS_NEEDNOQUOTE=" $OPTS_NEEDNOQUOTE $OPTS_NEEDNOQUOTE_DEPR "
OPTS_SENSITIVE=" $OPTS_SENSITIVE $OPTS_SENSITIVE_DEPR "
OPTS_LITERAL=" $OPTS_LITERAL $OPTS_LITERAL_DEPR "
OPTS_DEPRECATED=" $OPTS_NEEDQUOTE_DEPR $OPTS_NEEDNOQUOTE_DEPR $OPTS_SENSITIVE_DEPR $OPTS_LITERAL_DEPR "

# Remove configuration because it will be re-created.
rm -f /data/lenses-agent.conf
rm -f /data/security.conf

# This takes as argument a variable name and detects if it contains sensitive data
function detect_sensitive_variable {
    local var="$1"
    # shellcheck disable=SC2076
    if [[ "$OPTS_SENSITIVE" =~ " $var " ]]; then
        return 0
    fi
    if [[ "$var" == *"PASSWORD"* || "$var" == *"SECRET"* ]]; then
        return 0
    fi
    return 1
}

# This takes as arguments a variable name and a file (lenses-agent.conf or security.conf)
# and process the variable before adding it to the file (i.e convert to lowercase,
# check if it needs quotes, etc).
function process_variable {
    local var="$1"
    local config_file="$2"

    # Convert var name to lowercase
    conf="${var,,}"
    # Convert underscores in var name to stops
    conf="${conf//_/.}"

    if [[ "$OPTS_DEPRECATED" =~ " $var " ]]; then
        echo "WARN: Deprecated setting '$var' detected. Please remove it."
    fi

    # If setting needs to be quoted, write with quotes
    # This is ok because we need to pattern match with the spaces, so ignore sc
    # shellcheck disable=SC2076
    if [[ "$OPTS_NEEDQUOTE" =~ " $var " ]]; then
        echo "${conf}=\"${!var}\"" >> "$config_file"
        if detect_sensitive_variable "$var"; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=\"${!var}\""
        fi
        return 0
    fi

    # If settings must not have quotes, write without quotes.
    # shellcheck disable=SC2076
    if [[ "$OPTS_NEEDNOQUOTE" =~ " $var " ]]; then
        echo "${conf}=${!var}" >> "$config_file"
        if detect_sensitive_variable "$var"; then
            echo "${conf}=********"
            unset "${var}"
        else
            echo "${conf}=${!var}"
        fi
        return 0
    fi

    # Else try to detect if we need quotes.
    if [[ $OLD_QUOTING =~ $TRUE_REG ]]; then
        if [[ "${!var}" =~ .*[?:,.()*/|#!+].* ]]; then
            echo -n "[Variable needed quotes, old escaping] "
            echo "${conf}=\"${!var}\"" >> "$config_file"
        else
            echo "${conf}=${!var}" >> "$config_file"
        fi
   else
       # New quoting method tries to respect: https://github.com/lightbend/config/blob/main/HOCON.md#unquoted-strings
        if [[ "${!var}" =~ .*[\$\{\}\:\=\,\+\#\`\^\?\!\@\*\&\\\/\|].* ]] ||
               [[ "${!var}" =~ .*[[:space:]].* ]] ||
               [[ "${!var}" =~ .*[\]\[].* ]]; then
            echo -n "[Variable needed quotes] "
            echo "${conf}=\"${!var}\"" >> "$config_file"
        else
            echo "${conf}=${!var}" >> "$config_file"
        fi
    fi

    if detect_sensitive_variable "$var"; then
        echo "${conf}=********"
        unset "${var}"
    else
        echo "${conf}=${!var}"
    fi
}

DETECTED_LENFILE=false
if [[ -f /mnt/settings/lenses.conf && -f /mnt/settings/lenses-agent.conf ]]; then
    echo "Detected both '/mnt/settings/lenses.conf' and '/mnt/settings/lenses-agent.conf'. You must use only one. Container will fail in 30 seconds."
    sleep 30
    exit 1
elif [[ -f /mnt/settings/lenses-agent.conf ]]; then
    echo "Detected /mnt/settings/lenses-agent.conf."
    cp /mnt/settings/lenses-agent.conf /data/lenses-agent.conf
    if [[ $LC_KUBERNETES_MODE != true ]]; then
        echo "Will use file detected and ignore any environment variables!"
        DETECTED_LENFILE=true
    fi
elif [[ -f /mnt/settings/lenses.conf ]]; then
    echo "Detected /mnt/settings/lenses.conf."
    cp /mnt/settings/lenses.conf /data/lenses-agent.conf
    if [[ $LC_KUBERNETES_MODE != true ]]; then
        echo "Will use file detected and ignore any environment variables!"
        DETECTED_LENFILE=true
    fi
fi

DETECTED_SECFILE=false
if [[ -f /mnt/secrets/security.conf ]]; then
    echo "Detected /mnt/secrets/security.conf."
    cp /mnt/secrets/security.conf /data/security.conf
    if [[ $LC_KUBERNETES_MODE != true ]]; then
        echo "Will use file detected and ignore any environment variables!"
        DETECTED_SECFILE=true
    fi
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found one. Only an empty one should be used."
fi

# Create an empty security.conf to keep lenses happy
if [[ ! -f /data/security.conf ]]; then
    touch /data/security.conf
fi

# Add an separator to prepare for the autodetection of the env vars
# This line is important or else the first env var fails under certain circumstances
if [[ $DETECTED_LENFILE == false && $LC_KUBERNETES_MODE == true ]]; then
    echo -e "\n# Auto-detected env vars\n" >> /data/lenses-agent.conf
fi

# Add an separator to prepare for the autodetection of the env vars
# This line is important or else the first env var fails under certain circumstances
if [[ $DETECTED_SECFILE == false && $LC_KUBERNETES_MODE == true ]]; then
    echo -e "\n# Auto-detected env vars\n" >> /data/security.conf
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
    # shellcheck disable=SC2076
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
            process_variable "$var" /data/lenses-agent.conf
        fi
    fi
done

DETECTED_PROVISIONING_FILE=false
PROVISIONING_STATUS=""
# Only handle provisioning if using default path and no external lenses config is provided
if [[ "${LENSES_PROVISIONING_PATH}" == "/data/provisioning" && $DETECTED_LENFILE == false ]]; then
    if [[ -f "${LENSES_PROVISIONING_PATH}/provisioning.yaml" ]]; then
	echo "WARN: provisioning.yaml already exists at '${LENSES_PROVISIONING_PATH}/provisioning.yaml'. It will not be modified."
	PROVISIONING_STATUS="exists"
	DETECTED_PROVISIONING_FILE=true
    elif [[ -f /mnt/settings/provisioning.yaml ]]; then
	# This is bad practice, because provisioning can only check for
	# file updates in the directory it is being loaded from. Users
	# must set themselves the 'lenses.provisioning.path' to something
	# different that '/data/provisioning' if they want autodetection
	# to work. Also, in case the copied file is used, it requires all
	# referenced files (e.g., keystores) to have an absolute path
        echo "Detected /mnt/settings/provisioning.yaml."
        cp /mnt/settings/provisioning.yaml "${LENSES_PROVISIONING_PATH}/provisioning.yaml"
        DETECTED_PROVISIONING_FILE=true
        PROVISIONING_STATUS="copied_from_mount"
    elif [[ -n "${PROVISION_AGENT_KEY:-}" && -n "${PROVISION_HQ_URL:-}" ]]; then
        echo "Creating provisioning.yaml from environment variables."
        cat <<EOF > "${LENSES_PROVISIONING_PATH}/provisioning.yaml"
# AUTO-GENERATED by lenses-docker setup.sh - DO NOT EDIT MANUALLY
# This file will be regenerated on container restart if environment variables change
# Lenses HQ Connection
lensesHq:
    - name: lenses-hq
        version: 1
        tags: []
        configuration:
            server:
                value: "${PROVISION_HQ_URL}"
            port:
                value: 10000
            agentKey:
                value: "${PROVISION_AGENT_KEY}"
EOF
        DETECTED_PROVISIONING_FILE=true
        PROVISIONING_STATUS="created_autogenerated"
    else
        echo "Skipping provisioning.yaml creation: PROVISION_AGENT_KEY and PROVISION_HQ_URL not set."
        PROVISIONING_STATUS="skipped_no_env_vars"
    fi
else
    echo "Skipping provisioning.yaml creation: custom LENSES_PROVISIONING_PATH or external lenses config provided."
    PROVISIONING_STATUS="skipped"
fi

# Function to add a configuration if it does not already exists, in order to
# deal with settings that may be added via more that one FILECONTENT_ entries.
add_conf_if_not_exists(){
    local FILE=$1
    local CONFIG=$2
    # This isn't completely robust but all input is controlled by us,
    # we pass the CONFIG, not the user.
    local OPTION_NAME
    OPTION_NAME="$(sed -r -e 's/^\s*([^=]+)=.*/\1/' <<<"$CONFIG")"
    if ! grep -sqE "^\s*${OPTION_NAME}=" "$FILE"; then
        cat <<EOF >>"$FILE"
$CONFIG
EOF
    fi
}

# Function that takes a file as an argument and returns 'base64 -d' if the file
# seems to be encoded in base64, or 'cat' if it's not.
BASE64_REGEXP="^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
detect_file_decode_utility() {
    local DECODE="cat"
    if ! cat "${1}" | tr -d '\n' | grep -vsqE "$BASE64_REGEXP" ; then
        DECODE="base64 -d"
    fi
    echo "${DECODE}"
}

# Function that creates a truststore from a PEM file. Takes an input and output
# file as parameters. Password is hardcoded to 'changeit'.
create_truststore_from_pem() {
    # Awesome awk script to split pem files with many certificates from
    # https://stackoverflow.com/a/29997111
    local NUM_CERTS
    NUM_CERTS=$(grep -c 'END CERTIFICATE' "$1")
    for N in $(seq 0 $((NUM_CERTS - 1))); do
        ALIAS="${1%.*}-$N"
        cat "${1}" \
            | awk "n==$N { print }; /END CERTIFICATE/ { n++ }" \
            | /usr/bin/keytool \
                  -importcert \
                  -noprompt \
                  -trustcacerts \
                  -keystore "$2" \
                  -alias "${ALIAS}" \
                  -storepass changeit \
                  -storetype JKS
        rm -rf /tmp/vlxjre
    done
}

# Function that creates a keystore file from a private key and a certificate
# files in pem format. Takes the private key, certificate, and keystore to
# write as parameters. It cannot be run in parallel. Password and key passphrase
# are hardcoded to 'changeit'
create_keystore_from_pem() {
    openssl pkcs12 -export \
            -inkey "${1}" \
            -in "${2}" \
            -out /tmp/keystore.p12 \
            -name service \
            -passout pass:changeit
    /usr/bin/keytool \
        -importkeystore \
        -noprompt -v \
        -srckeystore /tmp/keystore.p12 \
        -srcstoretype PKCS12 \
        -srcstorepass changeit \
        -alias service \
        -deststorepass changeit \
        -destkeypass changeit \
        -destkeystore "${3}" \
        -deststoretype JKS
    rm -rf /tmp/vlxjre /tmp/keystore.p12
}

# Convert FILECONTENT_* env vars to files, so we can process them like the rest
mkdir -p /tmp/filecontent
for var in $(printenv | grep -E "^FILECONTENT_" | sed -e 's/=.*//'); do
    echo "${!var}" >> "/tmp/filecontent/${var}"
done

# Find side files (SSL trust/key stores, jaas, krb5) shared via
# mounts/secrets/env vars and process them
find /mnt/settings /mnt/secrets /run/secrets /tmp/filecontent -type f -name 'FILECONTENT_*' 2>/dev/null \
    | while read setting; do
    DECODE="$(detect_file_decode_utility "${setting}")"
    case "$setting" in
        */FILECONTENT_LENSES_SSL_KEYSTORE)
            $DECODE < "${setting}" > /data/lenses.jks
            chmod 400 /data/lenses.jks
            cat <<EOF >>/data/lenses-agent.conf
lenses.ssl.keystore.location=/data/lenses.jks
EOF
            # TODO: Use add_conf_if_not_exists to add processor settings
            # in order to avoid forcing users to use lenses.append.conf
            echo "File created. Sha256sum: $(sha256sum /data/lenses.jks)"
            ;;
        */FILECONTENT_LENSES_SSL_TRUSTSTORE)
            $DECODE < "${setting}" > /data/lenses-truststore.jks
            chmod 400 /data/lenses-truststore.jks
            cat <<EOF >>/data/lenses-agent.conf
lenses.ssl.truststore.location=/data/lenses-truststore.jks
EOF
            echo "File created. Sha256sum: $(sha256sum /data/lenses-truststore.jks)"
            ;;
        */FILECONTENT_LENSES_SSL_KEY_PEM)
            $DECODE < "${setting}" > /tmp/lenseskey.pem
            if [[ -f /tmp/lensescert.pem ]]; then
                create_keystore_from_pem /tmp/lenseskey.pem /tmp/lensescert.pem /data/lenses.jks
                rm -rf /tmp/lensescert.pem /tmp/lenseskey.pem
                chmod 400 /data/lenses.jks
                cat <<EOF >> /data/lenses-agent.conf
lenses.ssl.keystore.location=/data/lenses.jks
lenses.ssl.keystore.password="changeit"
lenses.ssl.key.password="changeit"
EOF
                echo "File created. Sha256sum: $(sha256sum /data/lenses.jks)"
            fi
            ;;
        */FILECONTENT_LENSES_SSL_CERT_PEM)
            $DECODE < "${setting}" > /tmp/lensescert.pem
            if [[ -f /tmp/lenseskey.pem ]]; then
                create_keystore_from_pem /tmp/lenseskey.pem /tmp/lensescert.pem /data/lenses.jks
                rm -rf /tmp/lensescert.pem /tmp/lenseskey.pem
                chmod 400 /data/lenses.jks
                cat <<EOF >> /data/lenses-agent.conf
lenses.ssl.keystore.location=/data/lenses.jks
lenses.ssl.keystore.password="changeit"
lenses.ssl.key.password="changeit"
EOF
                echo "File created. Sha256sum: $(sha256sum /data/lenses.jks)"
            fi
            ;;
        */FILECONTENT_JAAS)
            $DECODE < "${setting}" > /data/jaas.conf
            chmod 400 /data/jaas.conf
            export LENSES_OPTS="$LENSES_OPTS -Djava.security.auth.login.config=/data/jaas.conf"
            echo "File created. Sha256sum: $(sha256sum /data/jaas.conf)"
            ;;
        */FILECONTENT_KRB5)
            $DECODE < "${setting}" > /data/krb5.conf
            chmod 400 /data/krb5.conf
            export LENSES_OPTS="$LENSES_OPTS -Djava.security.krb5.conf=/data/krb5.conf"
            echo "File created. Sha256sum: $(sha256sum /data/krb5.conf)"
            ;;
        */FILECONTENT_JVM_SSL_TRUSTSTORE)
            $DECODE < "${setting}" > /data/jvm-truststore.jks
            echo "File created. Sha256sum: $(sha256sum /data/jvm-truststore.jks)"
            chmod 400 /data/jvm-truststore.jks
            export LENSES_OPTS="$LENSES_OPTS -Djavax.net.ssl.trustStore=/data/jvm-truststore.jks"
            ;;
        */FILECONTENT_JVM_SSL_TRUSTSTORE_PASSWORD)
            # Password cannot be in base64 because we cannot distinguish between
            # base64 and text in this case
            LENSES_OPTS="$LENSES_OPTS -Djavax.net.ssl.trustStorePassword=$(cat "${setting}")"
            export LENSES_OPTS
            ;;
        *)
            echo "Unknown filecontent at '$setting' was provided but won't be used."
            ;;
    esac
done
rm -rf /tmp/filecontent

# If not explicit security file set auto-generated:
DETECTED_SECCUSTOMFILE=false
if ! grep -sqE '^lenses.secret.file=' /data/lenses-agent.conf; then
    echo -e "\\nlenses.secret.file=/data/security.conf" >> /data/lenses-agent.conf
else
    # Setting this to true, so we can give a warning if the user provides a lenses.append.file
    DETECTED_SECCUSTOMFILE=true
fi

# Append Advanced Configuration Snippet
DETECTED_LENAPPENDFILE=false
if [[ -f /mnt/settings/lenses.append.conf && -f /mnt/settings/lenses-agent.append.conf ]]; then
    echo "WARN: there are two advanced configuration snippets to append '/mnt/settings/lenses-agent.append.conf' and '/mnt/settings/lenses.append.conf'. Only one should be used. The container will fail in 30 seconds."
    sleep 30
    exit 1
elif [[ -f /mnt/settings/lenses-agent.append.conf ]]; then
    echo -e "\n# lenses.append.conf" >> /data/lenses-agent.conf
    cat /mnt/settings/lenses.append.conf >> /data/lenses-agent.conf
    echo "Appending advanced configuration snippet to lenses-agent.conf"
    DETECTED_LENAPPENDFILE=true
elif [[ -f /mnt/settings/lenses.append.conf ]]; then
    echo -e "\n# lenses.append.conf" >> /data/lenses-agent.conf
    cat /mnt/settings/lenses.append.conf >> /data/lenses-agent.conf
    echo "Appending advanced configuration snippet to lenses-agent.conf."
    DETECTED_LENAPPENDFILE=true
fi
DETECTED_SECAPPENDFILE=false
if [[ -f /mnt/settings/security.append.conf ]]; then
    echo -e "\n# security.append.conf" >> /data/security.conf
    cat /mnt/settings/security.append.conf >> /data/security.conf
    echo "Appending advanced configuration snippet to security.conf."
    if [[ $DETECTED_SECCUSTOMFILE == true ]]; then
        echo "WARN: advanced configuration snippet may fail to be applied to user provided security.conf file."
    fi
    DETECTED_SECAPPENDFILE=true
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found a snippet to append."
fi

# Append Advanced Configuration via Env Vars (experimental)
DETECTED_LENAPPENDVAR=false
if [[ -n ${LENSES_APPEND_CONF} && -n ${LENSES_AGENT_APPEND_CONF} && ${EXPERIMENTAL} =~ $TRUE_REG ]]; then
    echo "WARN: there are two advanced configuration snippets to append 'LENSES_AGENT_APPEND_CONF' and 'LENSES_APPEND_CONF'. Only one should be used. The container will fail in 30 seconds."
    sleep 30
    exit 1
elif [[ -n ${LENSES_AGENT_APPEND_CONF} ]]; then
    echo -e "\n# LENSES_AGENT_APPEND_CONF" >> /data/lenses-agent.conf
    echo "${LENSES_AGENT_APPEND_CONF}" >> /data/lenses-agent.conf
    echo "Appending advanced configuration via LENSES_AGENT_APPEND_CONF to lenses-agent.conf"
    DETECTED_LENAPPENDVAR=true
elif [[ -n ${LENSES_APPEND_CONF} && ${EXPERIMENTAL} =~ $TRUE_REG ]]; then
    echo -e "\n# LENSES_APPEND_CONF" >> /data/lenses-agent.conf
    echo "${LENSES_APPEND_CONF}" >> /data/lenses-agent.conf
    echo "Appending advanced configuration via LENSES_APPEND_CONF to lenses-agent.conf"
    DETECTED_LENAPPENDVAR=true
fi
DETECTED_SECAPPENDVAR=false
if [[ -n ${SECURITY_APPEND_CONF} && ${EXPERIMENTAL} =~ $TRUE_REG  ]]; then
    echo -e "\n# SECURITY_APPEND_CONF" >> /data/security.conf
    echo "${SECURITY_APPEND_CONF}" >> /data/security.conf
    echo "Appending advanced configuration via LENSES_SECURITY_CONF to security.conf."
    if [[ $DETECTED_SECCUSTOMFILE == true ]]; then
        echo "WARN: advanced configuration snippet may fail to be applied to user provided security.conf file."
    fi
    DETECTED_SECAPPENDVAR=true
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found a snippet to append."
fi

# Clear empty values (just in case)
sed '/^\s*[^=]*=\s*$/d' -i /data/lenses-agent.conf /data/security.conf

# We created all needed files. Set a more permissive umask for data and logs
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

# If running as root and DEBUG_TOOLS is set, install tools for debugging
if [[ "$C_UID" == 0 ]] && [[ $DEBUG_TOOLS =~ $TRUE_REG ]]; then
    echo "Installing debugging tools. This can take a couple minutes."
    apt update -qq
    apt install -y \
        curl \
        dnsutils \
        htop \
        iproute2 \
        iputils-ping \
        lsof \
        net-tools \
        netcat \
        procps \
        tcpdump \
        vim \
        wget > /dev/null
elif [[ "$C_UID" != 0 ]] && [[ $DEBUG_TOOLS =~ $TRUE_REG ]]; then
    echo "WARN: DEBUG_TOOLS is set but you are not running as root. Ignoring."
fi

FORCE_ROOT_USER=${FORCE_ROOT_USER:-false}
if [[ "$C_UID" == 0 ]] && [[ $FORCE_ROOT_USER =~ $FALSE_REG ]]; then
    echo "Running as root. Will change data ownership to nobody:nogroup (65534:65534) and drop priviliges."
    # Directories first, files second, in logical/timeline order
    chown -R -f nobody:nogroup \
          /data/log \
          /data/kafka-streams-state \
          /data/plugins \
          /data/storage \
          /data/lenses-agent.conf \
          /data/security.conf \
	  /data/provisioning/provisioning.yaml \
          /data/logback.xml \
          /data/keystore.jks \
          /data/truststore.jks \
          /data/jvm-truststore.jks \
          /data/lenses.jks \
          /data/jaas.conf \
          /data/krb5.conf \
          /data/keytab || true
    chmod 750 -f \
          /data/log \
          /data/kafka-streams-state \
          /data/plugins \
          /data/storage || true
    chmod 640 -f \
          /data/lenses-agent.conf \
          /data/security.conf \
	  /data/provisioning/provisioning.yaml \
          /data/logback.xml \
          /data/keystore.jks \
          /data/truststore.jks \
          /data/jvm-truststore.jks \
          /data/lenses.jks \
          /data/jaas.conf \
          /data/krb5.conf \
          /data/keytab || true
    C_SUCMD=/usr/sbin/gosu
    C_SUID="nobody:nogroup"
else
    LOG_WRITEABLE=0
    STATE_WRITEABLE=0
    echo "Running as user:group $C_UID:$C_GID. Checking permissions."
    touch /data/log/lenses-test >/dev/null 2>&1 \
        && LOG_WRITEABLE=1 && rm /data/log/lenses-test
    [[ $LOG_WRITEABLE == 0 ]] \
        && echo "ERROR! /data/log/ is not writeable by the set user:group ($C_UID:$C_GID). You can ignore this error if you set a custom, writeable directory for logs."
    touch /data/kafka-streams-state/lenses-test >/dev/null 2>&1 \
        && STATE_WRITEABLE=1 && rm /data/kafka-streams-state/lenses-test
    [[ $STATE_WRITEABLE == 0 ]] \
        && echo "ERROR! /data/kafka-streams-state/ is not writeable by the set user:group ($C_UID:$C_GID). You can ignore this error if you set a custom, writeable directory for state."
fi

# Enable fastdata_agent for exporting metrics to prometheus
if [[ $PROMETHEUS_METRICS_PORT -ne 0 ]]; then
    export LENSES_OPTS="$LENSES_OPTS -javaagent:/opt/lensesio/fast_data_monitoring/jmx_prometheus_javaagent.jar=$PROMETHEUS_METRICS_PORT:/opt/lensesio/fast_data_monitoring/exporter.yml"
fi

# If PAUSE_EXEC is set, we wait for 10 minutes before starting lenses.
# This way we can go into the container and debug things before it exits.
if [[ $PAUSE_EXEC =~ $TRUE_REG ]]; then
    sleep 600
fi

if [[ -n $WAIT_SCRIPT ]]; then
    if [[ -f $WAIT_SCRIPT ]]; then
        eval "$WAIT_SCRIPT"
    elif [[ -f /usr/local/share/lensesio/wait-scripts/$WAIT_SCRIPT ]]; then
        WAIT_SCRIPT="/usr/local/share/lensesio/wait-scripts/$WAIT_SCRIPT"
        eval "$WAIT_SCRIPT"
    else
        echo "Wait script not found. Waiting for 120 seconds."
        sleep 120
    fi
fi

# In demo mode, register ourselves with HQ.
# We expect provisioning to set the agent key to the env var LENSESHQ_AGENT_KEY
DEMO_HQ_ENV_NAME=${DEMO_HQ_ENV_NAME:-demo}
DEMO_AGENTKEY_PATH=${DEMO_AGENTKEY_PATH:-}
DEMO_HQ_URL=${DEMO_HQ_URL:-}
DEMO_HQ_USER=${DEMO_HQ_USER:-}
DEMO_HQ_PASSWORD=${DEMO_HQ_PASSWORD:-}
if [[ -n $DEMO_HQ_URL && \
          -n $DEMO_HQ_USER && \
          -n $DEMO_HQ_PASSWORD || \
              -n $DEMO_AGENTKEY_PATH ]]; then
    echo "DEMO_HQ_URL, DEMO_HQ_USER, and DEMO_HQ_PASS or DEMO_AGENTKEY_PATH are set."
fi
if [[ -n $DEMO_AGENTKEY_PATH && \
          -f $DEMO_AGENTKEY_PATH ]] && \
          lenses -a "$DEMO_HQ_URL" -u "$DEMO_HQ_USER" -p "$DEMO_HQ_PASSWORD" environments list | grep -sq "$DEMO_HQ_ENV_NAME"; then
    echo "WARNING! Stored DEMO_AGENTKEY_PATH for existing environment found. This is insecure, meant only for demos."
    LENSESHQ_AGENT_KEY="$(cat "$DEMO_AGENTKEY_PATH")"
    export LENSESHQ_AGENT_KEY
elif [[ -n $DEMO_HQ_URL && \
            -n $DEMO_HQ_USER && \
            -n $DEMO_HQ_PASSWORD ]]; then
    echo "WARNING! We will try to register ourselves to HQ mode. This is insecure, meant only for demos."
    for ((i=0;i<20;i++)); do curl -s -o /dev/null "$DEMO_HQ_URL" && break; sleep 3; done
    LENSESHQ_AGENT_KEY="$(lenses -a "$DEMO_HQ_URL" -u "$DEMO_HQ_USER" -p "$DEMO_HQ_PASSWORD" \
                             environments create --tier development --name "$DEMO_HQ_ENV_NAME" \
                          | grep -Eo "agent_key_[A-Za-z0-9_]+")"
    if [[ -n $LENSESHQ_AGENT_KEY ]]; then
        echo "Registered to HQ. Agent key: $LENSESHQ_AGENT_KEY"
        export LENSESHQ_AGENT_KEY
        if [[ -n $DEMO_AGENTKEY_PATH ]]; then
            echo "Storing demo key to survive restarts."
            echo "$LENSESHQ_AGENT_KEY" > "$DEMO_AGENTKEY_PATH"
        fi
    else
        echo "Failed to register to HQ."
    fi
fi

# Print information about possible overrides.
echo "Setup script finished."
if [[ $DETECTED_LENFILE =~ $TRUE_REG ]]; then
    echo "You provided a 'lenses-agent.conf' or 'lenses.conf' file. Autodetected settings will be ignored."
fi
if [[ $DETECTED_SECFILE =~ $TRUE_REG ]]; then
    echo "You provided a 'security.conf' file. Autodetected security settings will be ignored."
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found one. Only an empty one should be used."
fi
if [[ $DETECTED_SECCUSTOMFILE =~ $TRUE_REG ]]; then
    echo "You provided a custom location for 'security.conf'. Autodetected security settings may be ignored."
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found one. Only an empty one should be used."
fi
if [[ $DETECTED_LENAPPENDFILE =~ $TRUE_REG ]]; then
    echo "You provided a 'lenses-agent.append.conf' or 'lenses.append.conf' file. It may override some autodetected settings."
fi
if [[ $DETECTED_SECAPPENDFILE =~ $TRUE_REG ]]; then
    echo "You provided a 'security.append.conf' file. It may override some autodetected settings."
    echo "Warning: the Lenses Agent should not have a 'security.conf' but we found a snippet to append."
fi
if [[ $DETECTED_LENAPPENDVAR =~ $TRUE_REG && $EXPERIMENTAL =~ $TRUE_REG ]]; then
    echo "You set the LENSES_AGENT_APPEND_CONF or LENSES_APPEND_CONF environment variable. It may override some autodetected settings."
fi
if [[ $DETECTED_SECAPPENDVAR =~ $TRUE_REG && $EXPERIMENTAL =~ $TRUE_REG ]]; then
    echo "You set the SECURITY_APPEND_CONF environment variable. It may override some autodetected settings."
fi

# Provisioning status messages
case "$PROVISIONING_STATUS" in
    "exists")
	echo "A 'provisioning.yaml' file was detected under '/data/provisioning' (default LENSES_PROVISIONING_PATH)."
	echo "Warning: Any other provisioning setting or file will be ignored. This is normal if managing provisioning via HQ."
	;;
    "copied_from_mount")
        echo "You provided '/mnt/settings/provisioning.yaml' but did not set the LENSES_PROVISIONING_PATH."
	# Do not mention the full path, things under /data are not to be managed by users
	echo "Warning: the provisioning file was copied under '/data', but may not work."
        ;;
    "created_autogenerated")
        echo "'provisioning.yaml' was auto-generated from environment variables."
        ;;
    "skipped_no_env_vars")
        ;;
    "skipped")
        ;;
    *)
        ;;
esac

echo "Docker environment initialized. Starting Lenses."
echo "================================================"

cd /data
exec $C_SUCMD $C_SUID /opt/lenses-agent/bin/lenses-agent /data/lenses-agent.conf
