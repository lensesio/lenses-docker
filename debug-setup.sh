#!/usr/bin/env bash

INSTALL_LIST=""

for i in procps emacs24-nox vim htop curl dnsutils lsof net-tools; do
    echo "Install $i?"
    select yn in "Yes" "No"; do
        case $yn in
            Yes )
                INSTALL_LIST="$INSTALL_LIST $i"
                break;;
            No )
            break;;
        esac
    done
done

apt-get update
apt-get install -y $INSTALL_LIST

echo "Install jmxterm to debug JMX connections?"
select yn in "Yes" "No"; do
    case $yn in
        Yes)
            mkdir -p /usr/share/landoop/tools/
            wget https://archive.landoop.com/third-party/jmxterm/jmxterm-1.0.0-SNAPSHOT-uber.jar \
                 -O /usr/share/landoop/tools/jmxterm-1.0.0.jar
            echo "Installed at '/usr/share/landoop/tools/jmxterm-1.0.0.jar'."
            echo "Run with: '/opt/lenses/jre8u131/bin/java -jar /usr/share/landoop/tools/jmxterm-1.0.0.jar'"
            break;;
        No)
            break;;
    esac
done

