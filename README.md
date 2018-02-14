# Lenses™ for Apache Kafka

This is the official image of Landoop’s Lenses for Apache Kafka software.

Lenses is a Streaming Data Management Platform. It enhances Kafka with a web user interface and vital enterprise capabilities that enable engineering and data teams to query real time data, create and monitor Kafka topologies with rich integrations to other systems and gain operational awareness of their clusters.

Please visit our [website](https://www.landoop.com/) or the [documentation pages](https://lenses.stream) to learn more.


## The Docker Image

This image is aimed for our enterprise clients, though anyone with a free developer license may use it. Visit our [download page](https://www.landoop.com/downloads/) to get a free developer license or an enterprise trial.
Only Lenses is included in this docker. Our development environment image, which additionally includes Kafka, Connect, Schema Registry and our open-source Stream Reactor collection of connectors can be found as `landoop/kafka-lenses-dev`.

This image has to be run alongside a Kafka cluster.


## How to run

In the current iteration `landoop/lenses` uses environment variables for configuration. For any lenses configuration option, set an environment variable by converting the option name to uppercase and with dots replaced by underscores. As an example `lenses.port` should be converted to `LENSES_PORT`. Optionally settings may be mount as volumes under `/mnt/settings` or `/mnt/secrets`. As an example you could set —file— volume `/mnt/settings/LENSES_PORT` with the port number as the content of the file.

A brief example of a docker-compose file to setup Lenses, would be:

```yaml
version: '2'
services:
  lenses:
    image: landoop/lenses
    environment:
      LENSES_PORT: 9991
      LENSES_KAFKA_BROKERS: "PLAINTEXT://broker.1.url:9092,PLAINTEXT://broker.2.url:9092"
      LENSES_ZOOKEEPER_HOSTS: "zookeeper.1.url:2181,zookeeper.2.url:2181/znode"
      LENSES_SCHEMA_REGISTRY_URLS: "http://schema.registry.1.url:8081,http://schema.registry.2.url:8081"
      LENSES_CONNECT_CLUSTERS: '[{name: "production", url: "http://connect.worker.1.url:8083,http://connect.worker.2.url:8083", statuses: "connect-statuses", configs: "connect-configs", offsets: "connect-offsets"}]'
      # For JMX you need to enumerate all your instances. We are working to improve this. You can skip the brokers (we autodetect them).
      LENSES_JMX_BROKERS: "broker.1.url:9581,broker.2.url:9581,broker.3.url:9581"
      LENSES_JMX_SCHEMA_REGISTRY: "schema.registry.1.url:9582,schema.registry.2.url:9582"
      LENSES_JMX_ZOOKEEPERS: "zookeeper.1.url:9585,zookeeper.2.url,zookeeper.1.url:9585,zookeeper.3.url:9585"
      LENSES_JMX_CONNECT: '[{production: "connect.worker.1.url:9584,connect.worker.2.url:9584,connect.worker.3.url:9584"}]'
      LENSES_SECURITY_MODE: BASIC
      # Secrets can also be passed as files. Check _examples/
      LENSES_SECURITY_USERS: |
        [
          {"username": "admin", "password": "admin", "displayname": "Lenses Admin", "roles": ["admin", "write", "read"]},
          {"username": "writer", "password": "writer", "displayname": "Lenses Writer", "roles": ["read", "write"]},
          {"username": "reader", "password": "reader", "displayname": "Lenses Reader", "roles": ["read"]},
          {"username": "nodata", "password": "nodata", "displayname": "Lenses NoData", "roles": ["nodata"]}
        ]
    ports:
      - 9991:9991
    volumes:
      - ./license.json:/license.json
    # This is only need in some cases, where you run docker on a server that also hosts a service from the Kafka cluster
    network_mode: host
```

The docker image has two volumes where data are saved: `/data/log` for logs and `/data/kafka-streams-state` for storing the state of Lenses SQL processors. Depending on your queries and the topics volume, the latter can become pretty large. You should monitor space and plan for adequate capacity. Maintaining the streams state directory between Lenses restarts is mandatory for the SQL processors to be able to continue from where they left.

The container starts with root privileges and drops to `nobody:nogroup` (`65534:65534`) before running Lenses. If you start the image as a custom `user:group`, it falls under your responsibility to make sure that the two volumes are writeable by the custom `user:group`.

### The license file

Lenses require a license file in order to start. It may be passed to the container via three methods:

- As a file, mounted at /license.json or /mnt/secrets/license.json (e.g `-v /path/to/license.json:/license.json`)
- As the contents of the environment variable LICENSE (e.g `-e LICENSE="$(cat license.json)"`)
- As a downloadable URL via LICENSE_URL (e.g `-e LICENSE_URL="https://license.url/"`)

---

For more information, please visit our [documentation](https://www.landoop.com/docs/lenses/). Enterprise customers may use the support channels made available to them. Developer Edition users are encouraged to visit our [gitter chat](https://gitter.im/Landoop/support). We are always happy to help and hear from you.

With respect,

The Lenses Team.

---

Copyright 2018, Landoop LTD
