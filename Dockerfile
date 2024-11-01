ARG LENSES_BASE_VERSION=6.0
ARG LENSES_ARCHIVE=remote
ARG LENSES_VERSION=5.5.10
ARG LENSESCLI_ARCHIVE=remote
ARG LENSESCLI_VERSION=5.5.3

# This is the default image we use for installing Lenses
FROM alpine AS archive_remote
ONBUILD ARG AD_UN
ONBUILD ARG AD_PW
ONBUILD ARG LENSES_VERSION LENSES_BASE_VERSION
ONBUILD ARG AD_URL=https://archive.lenses.io/lenses/${LENSES_BASE_VERSION}/lenses-${LENSES_VERSION}-linux64.tar.gz
ONBUILD RUN apk add --no-cache wget \
        && echo "progress = dot:giga" | tee /etc/wgetrc \
        && mkdir -p /opt  \
        && echo "$AD_URL $AD_FILENAME" \
        && if [ -z "$AD_URL" ]; then exit 0; fi && wget $AD_UN $AD_PW "$AD_URL" -O /lenses.tgz \
        && tar xf /lenses.tgz -C /opt \
        && rm /lenses.tgz

# This image gets Lenses from a local file instead of a remote URL
FROM alpine AS archive_local
ONBUILD ARG AD_FILENAME
ONBUILD RUN mkdir -p /opt
ONBUILD ADD $AD_FILENAME /opt

# This image gets a custom Lenses frontend from a local file
FROM archive_local AS archive_local_with_ui
ONBUILD ARG UI_FILENAME
ONBUILD ADD $UI_FILENAME /opt
ONBUILD RUN rm -rf /opt/lenses/ui \
            && mv /opt/dist /opt/lenses/ui \
            && sed \
                 -e "s/export LENSESUI_REVISION=.*/export LENSESUI_REVISION=$(cat /opt/lenses/ui/build.info | cut -f 2 -d ' ')/" \
                 -i /opt/lenses/bin/lenses

# This image is here to just trigger the build of any of the above 3 images
FROM archive_${LENSES_ARCHIVE} AS archive
# Add jmx_exporter
ARG FAST_DATA_AGENT_URL=https://archive.landoop.com/tools/fast_data_monitoring/fast_data_monitoring-2.2.tar.gz
RUN mkdir -p /opt/lensesio/ \
    && wget "$FAST_DATA_AGENT_URL" -O /fda.tgz \
    && tar xf /fda.tgz -C /opt/lensesio \
    && rm /fda.tgz

# This is the default image we use for installing lenses-cli
FROM alpine AS lenses_cli_remote
ONBUILD ARG CAD_UN
ONBUILD ARG CAD_PW
ONBUILD ARG LENSESCLI_VERSION LENSES_BASE_VERSION
ONBUILD ARG TARGETARCH TARGETOS
ONBUILD ARG LC_URL="https://archive.lenses.io/lenses/${LENSES_BASE_VERSION}/cli/lenses-cli-${LENSESCLI_VERSION}-${TARGETOS}-${TARGETARCH}.tar.gz"
ONBUILD RUN wget $CAD_UN $CAD_PW "$LC_URL" -O /lenses-cli.tgz \
          && tar xzf /lenses-cli.tgz --strip-components=1 -C /usr/bin/ lenses-cli-${TARGETOS}-${TARGETARCH}/hq \
          && rm -f /lenses-cli.tgz

# This image gets Lenses from a local file instead of a remote URL
FROM alpine AS lenses_cli_local
ONBUILD ARG LC_FILENAME
ONBUILD ARG TARGETARCH TARGETOS
ONBUILD RUN mkdir -p /lenses-cli
ONBUILD COPY $LC_FILENAME /lenses-cli.tgz
ONBUILD RUN tar xzf /lenses-cli.tgz --strip-components=1 -C /usr/bin lenses-cli-${TARGETOS}-${TARGETARCH}/hq

# This image is here to just trigger the build of any of the above 3 images
ARG LENSESCLI_ARCHIVE
FROM lenses_cli_${LENSESCLI_ARCHIVE} AS lenses_cli

# The final Lenses image for compatibility with older versions
FROM debian:bullseye-slim AS lenses_debian
LABEL org.opencontainers.image.authors="Marios Andreopoulos <marios@lenses.io>"
LABEL org.opencontainers.image.ref.name="lensesio/lenses"
LABEL org.opencontainers.image.version=${LENSES_VERSION}
LABEL org.opencontainers.imave.vendor="Lenses.io"

# Update, install tooling and some basic setup
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        default-jre-headless \
        dumb-init \
        gosu \
    && rm -rf /var/lib/apt/lists/* \
    && echo 'export PS1="\[\033[1;31m\]\u\[\033[1;33m\]@\[\033[1;34m\]lenses \[\033[1;36m\]\W\[\033[1;0m\] $ "' \
            | tee -a /root/.bashrc >> /etc/bash.bashrc \
    && mkdir -p /mnt/settings /mnt/secrets

ADD setup.sh debug-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup.sh /usr/local/bin/debug-setup.sh
COPY /filesystem /

# PLACEHOLDER: This line can be used to inject code if needed, please do not remove #

# Add Lenses
COPY --from=archive /opt /opt

# Add Lenses CLI
COPY --from=lenses_cli /usr/bin/hq /usr/bin/hq

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

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/setup.sh"]


# The final Lenses image
FROM ubuntu:22.04
ARG LENSES_VERSION
LABEL org.opencontainers.image.authors="Marios Andreopoulos <marios@lenses.io>"
LABEL org.opencontainers.image.ref.name="lensesio/lenses"
LABEL org.opencontainers.image.version=${LENSES_VERSION}
LABEL org.opencontainers.imave.vendor="Lenses.io"

# Update, install tooling and some basic setup
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        default-jre-headless \
        dumb-init \
        gosu \
    && rm -rf /var/lib/apt/lists/* \
    && echo 'export PS1="\[\033[1;31m\]\u\[\033[1;33m\]@\[\033[1;34m\]lenses \[\033[1;36m\]\W\[\033[1;0m\] $ "' \
            | tee -a /root/.bashrc >> /etc/bash.bashrc \
    && mkdir -p /mnt/settings /mnt/secrets

ADD setup.sh debug-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup.sh /usr/local/bin/debug-setup.sh
COPY /filesystem /

# PLACEHOLDER: This line can be used to inject code if needed, please do not remove #

# Add Lenses
COPY --from=archive /opt /opt

# Add Lenses CLI
COPY --from=lenses_cli /usr/bin/hq /usr/bin/hq

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

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/setup.sh"]
