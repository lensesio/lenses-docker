# Lenses Archive
ARG LENSES_ARCHIVE=remote
ARG AD_URL=https://archive.lenses.io/lenses/4.3/lenses-4.3.8-linux64.tar.gz
# Lenses Cli
ARG LENSESCLI_ARCHIVE=remote
ARG LC_VERSION="4.3.6"
ARG LC_URL="https://archive.lenses.io/lenses/4.3/cli/lenses-cli-linux-amd64-$LC_VERSION.tar.gz"

# This is the default image we use for installing Lenses
FROM alpine as archive_remote
ONBUILD ARG AD_UN
ONBUILD ARG AD_PW
ONBUILD ARG AD_URL
ONBUILD RUN apk add --no-cache wget \
        && echo "progress = dot:giga" | tee /etc/wgetrc \
        && mkdir -p /opt  \
        && echo "$AD_URL $AD_FILENAME" \
        && if [ -z "$AD_URL" ]; then exit 0; fi && wget $AD_UN $AD_PW "$AD_URL" -O /lenses.tgz \
        && tar xf /lenses.tgz -C /opt \
        && rm /lenses.tgz

# This image gets Lenses from a local file instead of a remote URL
FROM alpine as archive_local
ONBUILD ARG AD_FILENAME
ONBUILD RUN mkdir -p /opt
ONBUILD ADD $AD_FILENAME /opt

# This image gets a custom Lenses frontend from a local file
FROM archive_local as archive_local_with_ui
ONBUILD ARG UI_FILENAME
ONBUILD ADD $UI_FILENAME /opt
ONBUILD RUN rm -rf /opt/lenses/ui \
            && mv /opt/dist /opt/lenses/ui \
            && sed \
                 -e "s/export LENSESUI_REVISION=.*/export LENSESUI_REVISION=$(cat /opt/lenses/ui/build.info | cut -f 2 -d ' ')/" \
                 -i /opt/lenses/bin/lenses

# This image is here to just trigger the build of any of the above 3 images
FROM archive_${LENSES_ARCHIVE} as archive

# This is the default image we use for installing lenses-cli
FROM alpine as lenses_cli_remote
ONBUILD ARG CAD_UN
ONBUILD ARG CAD_PW
ONBUILD ARG LC_VERSION
ONBUILD ARG LC_URL
ONBUILD RUN wget $CAD_UN $CAD_PW "$LC_URL" -O /lenses-cli.tgz \
          && tar xzf /lenses-cli.tgz --strip-components=1 -C /usr/bin/ lenses-cli-linux-amd64-$LC_VERSION/lenses-cli \
          && rm -f /lenses-cli.tgz

# This image gets Lenses from a local file instead of a remote URL
FROM alpine as lenses_cli_local
ONBUILD ARG LC_FILENAME
ONBUILD RUN mkdir -p /lenses-cli
ONBUILD COPY $LC_FILENAME /lenses-cli.tgz
ONBUILD RUN tar xzf /lenses-cli.tgz --strip-components=1 -C /usr/bin

# This image is here to just trigger the build of any of the above 3 images
ARG LENSESCLI_ARCHIVE
FROM lenses_cli_${LENSESCLI_ARCHIVE} as lenses_cli

# The final Lenses image
FROM debian:bullseye
MAINTAINER Marios Andreopoulos <marios@lenses.io>

# Update, install tooling and some basic setup
RUN apt-get update && apt-get install -y \
        curl \
        default-jre-headless \
        gosu \
        netcat \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && echo "progress = dot:giga" | tee /etc/wgetrc \
    && wget https://gitlab.com/andmarios/checkport/uploads/3903dcaeae16cd2d6156213d22f23509/checkport \
            -O /usr/local/bin/checkport \
    && wget https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64 \
            -O /usr/local/bin/dumb-init \
    && chmod +755 /usr/local/bin/checkport /usr/local/bin/dumb-init \
    && echo 'export PS1="\[\033[1;31m\]\u\[\033[1;33m\]@\[\033[1;34m\]lenses \[\033[1;36m\]\W\[\033[1;0m\] $ "' \
            | tee -a /root/.bashrc >> /etc/bash.bashrc \
    && mkdir -p /mnt/settings /mnt/secrets

# Add jmx_exporter
ARG FAST_DATA_AGENT_URL=https://archive.landoop.com/tools/fast_data_monitoring/fast_data_monitoring-2.1.tar.gz
RUN mkdir -p /opt/landoop/ \
    && wget "$FAST_DATA_AGENT_URL" -O /fda.tgz \
    && tar xf /fda.tgz -C /opt/landoop \
    && rm /fda.tgz

# Add fastdata-sd
ARG FASTDATA_SD_URL=https://archive.landoop.com/tools/fastdata-sd/fastdata-sd.tar.gz
RUN wget "$FASTDATA_SD_URL" -O /fdsd.tgz \
    && tar xf /fdsd.tgz -C /usr/local/bin \
    && rm /fdsd.tgz

ADD setup.sh debug-setup.sh service-discovery.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup.sh /usr/local/bin/debug-setup.sh /usr/local/bin/service-discovery.sh
COPY /filesystem /

# PLACEHOLDER: This line can be used to inject code if needed, please do not remove #

# Add Lenses
COPY --from=archive /opt /opt

# Add Lenses CLI
ARG LC_VERSION
COPY --from=lenses_cli /usr/bin/lenses-cli /usr/bin/lenses-cli

ARG BUILD_BRANCH
ARG BUILD_COMMIT
ARG BUILD_TIME
ARG DOCKER_REPO=local
RUN grep 'export LENSES_REVISION'      /opt/lenses/bin/lenses | sed -e 's/export //' | tee /build.info \
    && grep 'export LENSESUI_REVISION' /opt/lenses/bin/lenses | sed -e 's/export //' | tee -a /build.info \
    && grep 'export LENSES_VERSION'    /opt/lenses/bin/lenses | sed -e 's/export //' | tee -a /build.info \
    && echo "BUILD_BRANCH=${BUILD_BRANCH}"  | tee -a /build.info \
    && echo "BUILD_COMMIT=${BUILD_COMMIT}"  | tee -a /build.info \
    && echo "BUILD_TIME=${BUILD_TIME}"      | tee -a /build.info \
    && echo "DOCKER_REPO=${DOCKER_REPO}"    | tee -a /build.info

EXPOSE 9991

WORKDIR /
RUN mkdir -p /data /data/kafka-streams-state /data/log /data/plugins /data/storage \
    && chmod -R 777 /data
VOLUME ["/data/kafka-streams-state", "/data/log", "/data/plugins", "/data/storage"]

ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["/usr/local/bin/setup.sh"]
