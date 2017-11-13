#!/usr/bin/env bash

INSTALL_LIST=""

for i in procps emacs24-nox vim htop curl; do
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
