FROM debian:latest
MAINTAINER Marios Andreopoulos <marios@landoop.com>

# Update, install tooling and some basic setup
RUN apt-get update && apt-get install -y \
        wget \
        gosu \
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

# Install lenses
ARG AD_UN
ARG AD_PW
ARG AD_URL=https://archive.landoop.com/lenses/2.1/lenses-2.1.2-linux64.tar.gz
RUN wget $AD_UN $AD_PW "$AD_URL" -O /lenses.tgz \
    && tar xf /lenses.tgz -C /opt \
    && rm /lenses.tgz

# Add jmx_exporter
ARG FAST_DATA_AGENT_URL=https://archive.landoop.com/tools/fast_data_monitoring/fast_data_monitoring-2.0-preview.tar.gz
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
VOLUME ["/data/kafka-streams-state", "/data/log"]
RUN chmod 777 /data

ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["/usr/local/bin/setup.sh"]
