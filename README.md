## Build

    docker build -t landoop/lenses-for-kafka .

## Run

With default settings (e.g you have fast-data-dev running with `--net=host`):

    docker run --rm -it -v /path/to/license.json:/license.json landoop/lenses-for-kafka

Custom settings:

    docker run --rm -it \
        -v /path/to/license.json:/license.json \
        -e LENSES_ZOOKEEPER_HOSTS='"localhost:2181"' \
        -e LENSES_PORT=24005 \
        -e LENSES_JMX_BROKERS='"localhost:9581"' \
        landoop/lenses-for-kafka

## See version

    docker run --rm -it landoop/lenses-for-kafka cat /build.info
