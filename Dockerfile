FROM alpine
MAINTAINER Marios Andreopoulos <marios@landoop.com>

# Update, install tooling and some basic setup
RUN apk add --no-cache \
        bash coreutils \
        wget curl \
        tar gzip bzip2 \
        supervisor \
        sqlite \
        libstdc++ \
        openssl \
    && echo "progress = dot:giga" | tee /etc/wgetrc \
    && mkdir /opt \
    && wget https://gitlab.com/andmarios/checkport/uploads/3903dcaeae16cd2d6156213d22f23509/checkport -O /usr/local/bin/checkport \
    && chmod +x /usr/local/bin/checkport \
    && mkdir /etc/supervisord.d

# Create Landoop configuration directory
RUN mkdir /usr/share/landoop

# Install lenses
ARG AD_UN=itsmemario
ARG AD_PW=marioitsme
RUN wget --user $AD_UN --password $AD_PW https://archive.devops.landoop.com/pub/lenses-0.1-linux64.tar.gz -O /lenses.tgz \
    && tar xf /lenses.tgz -C /opt \
    && rm /lenses.tgz


# Add Kafka Lenses
RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/unreleased/glibc-2.26-r0.apk \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/unreleased/glibc-bin-2.26-r0.apk \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/unreleased/glibc-i18n-2.26-r0.apk \
    &&  apk add --no-cache --allow-untrusted glibc-2.26-r0.apk glibc-bin-2.26-r0.apk glibc-i18n-2.26-r0.apk

# Add dumb init and quickcert
RUN wget https://github.com/Yelp/dumb-init/releases/download/v1.2.0/dumb-init_1.2.0_amd64 -O /usr/local/bin/dumb-init \
    && chmod 0755 /usr/local/bin/dumb-init

RUN echo \
         'export PS1="\[\033[1;31m\]\u\[\033[1;33m\]@\[\033[1;34m\]fast-data-dev \[\033[1;36m\]\W\[\033[1;0m\] $ "' \
         > /root/.bashrc

ADD setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup.sh

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

EXPOSE 24005
ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["/usr/local/bin/setup.sh"]
