#!/usr/bin/env bash

INSTALL_LIST=""

for i in procps emacs24-nox vim htop curl dnsutils lsof net-tools tcpdump; do
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
            mkdir -p /usr/share/lensesio/tools/
            wget https://archive.lenses.io/third-party/jmxterm/jmxterm-1.0.0-SNAPSHOT-uber.jar \
                 -O /usr/share/lensesio/tools/jmxterm-1.0.0.jar
            echo "Installed at '/usr/share/lensesio/tools/jmxterm-1.0.0.jar'."
            echo "Run with: '/opt/lenses/jre/bin/java -jar /usr/share/lensesio/tools/jmxterm-1.0.0.jar'"
            break;;
        No)
            break;;
    esac
done

# echo "Install lenses-cli to access Lenses from the command line?"
# select yn in "Yes" "No"; do
#     case $yn in
#         Yes)
#             wget https://archive.lenses.io/lenses/4.0/cli/lenses-cli-linux-amd64-latest.tar.gz \
#                  -O /tmp/lenses-cli.tgz
#             tar xf /tmp/lenses-cli.tgz --strip-components=1 -C /tmp/
#             cp /tmp/lenses-cli /usr/local/bin/
#             echo "Installed at '/usr/local/bin/lenses-cli'."
#             echo "Run with: 'lenses-cli'"
#             break;;
#         No)
#             break;;
#     esac
# done
