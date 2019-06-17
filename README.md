# Lenses® for Apache Kafka

This is the official Docker for [Lenses](https://lenses.io/kafka-lenses) that
enables you to:

* View and Query Kafka Topic Data (Avro & JSon) - Browse and query with Lenses
  SQL
* View data topologies and monitor every aspect of your Kafka cluster
* View and manage your Data Schemas
* Build and monitor ETL pipelines with open source Kafka Connectors
* Execute KStreams processors instrumented in SQL in Kubernetes or Connector
  workers
* Set up alerting and external notifications on liveniness of streaming systems
* Data governance: Auditing on all actions, data lineage & multi-tenancy
* Fine-grained security. Role based access with LDAP support
* Manage Quotas, ACLs

As a state-less application lenses fits naturally in containers and run on
**Kubernetes** or **Openshift**. It integrates and helps you instrument and view
your streaming data pipelines; as well as operate them with confidence !

The documentation is always available at https://docs.lenses.io and data
engineering talk is on [Slack](https://launchpass.com/landoop-community)

## The Docker Image

**Please check out the
[docker image documentation at docs.lenses.io](https://docs.lenses.io/install_setup/deployment-options/docker-deployment.html)
for the most recent docs and the complete set of features, settings and tweak
knobs.**


This image is aimed for our enterprise clients, though anyone with a free
developer license may use it. Visit
our [download page](https://lenses.io/downloads/) to get a free developer
license or an enterprise trial.  Only Lenses is included in this docker. Our
development environment image, which additionally includes Kafka, Connect,
Schema Registry and our open-source Stream Reactor collection of connectors can
be found as `landoop/kafka-lenses-dev`.

This image has to be run alongside a Kafka cluster.


## How to run

In the current iteration `landoop/lenses` uses environment variables as the
primary means for configuration and alternatively configuration files.

### Setup with environment variables

For any lenses configuration option, set an environment variable by converting
the option name to uppercase and with dots replaced by underscores. As an
example `lenses.port` should be converted to `LENSES_PORT`. Optionally settings
may be mount as volumes under `/mnt/settings` or `/mnt/secrets`. As an example
you could set —file— volume `/mnt/settings/LENSES_PORT` with the port number as
the content of the file.

A brief example of a docker-compose file to setup Lenses, would be:

```yaml
version: '2'
services:
  lenses:
    image: landoop/lenses
    environment:
      LENSES_PORT: 9991
      LENSES_KAFKA_BROKERS: "PLAINTEXT://broker.1.url:9092,PLAINTEXT://broker.2.url:9092"

      # # If you have enabled JMX for your brokers, set the port here
      # LENSES_KAFKA_METRICS_DEFAULT_PORT: 9581

      # # If you use AVRO, configure the Schema Registry
      # LENSES_SCHEMA_REGISTRY_URLS: |
      #   [
      #     {url:"http://schema.registry.1.url:8081"},
      #     {url:"http://schema.registry.2.url:8081"}
      #   ]

      # # If you use Kafka Connect, configure the workers.
      # LENSES_KAFKA_CONNECT_CLUSTERS: |
      #   [
      #     {
      #       name:"data_science",
      #       urls: [
      #         {url:"http://connect.worker.1.url:8083"},
      #         {url:"http://connect.worker.2.url:8083"}
      #       ],
      #       statuses:"connect-statuses-cluster-a",
      #       configs:"connect-configs-cluster-a",
      #       offsets:"connect-offsets-cluster-a"
      #     }
      #   ]
      # LENSES_ZOOKEEPER_HOSTS: |
      #   [
      #     {url:"zookeeper.1.url:2181"},
      #     {url:"zookeeper.2.url:2181"}
      #   ]

      LENSES_SECURITY_MODE: BASIC
      # Secrets can also be passed as files. Check _examples/
      LENSES_SECURITY_GROUPS: |
        [
          {"name": "adminGroup", "roles": ["Admin", "DataPolicyWrite", "AlertsWrite", "TableStorageWrite"]},
          {"name": "readGroup",  "roles": ["Read"]}
        ]
      LENSES_SECURITY_USERS: |
        [
          {"username": "admin", "password": "admin", "displayname": "Lenses Admin", "groups": ["adminGroup"]},
          {"username": "read", "password": "read", "displayname": "Read Only", "groups": ["readGroup"]}
        ]
    ports:
      - 9991:9991
      - 9102:9102
    volumes:
      - ./license.json:/license.json
    network_mode: host
```

The docker image has two volumes where data are saved: `/data/log` for logs and
`/data/kafka-streams-state` for storing the state of Lenses SQL
processors. Depending on your queries and the topics volume, the latter can
become pretty large. You should monitor space and plan for adequate
capacity. Maintaining the streams state directory between Lenses restarts is
mandatory for the SQL processors to be able to continue from where they left.

The container starts with root privileges and drops to `nobody:nogroup`
(`65534:65534`) before running Lenses. If you start the image as a custom
`user:group`, it falls under your responsibility to make sure that the two
volumes are writeable by the custom `user:group`.

### Setup with configuration files

Lenses software configuration is driven by two files: `lenses.conf` and
`security.conf`. In the docker image we create them automatically from
environment variables but it is possible to set directly these files instead.

Create your configuration files according to
the
[documentation](https://docs.lenses.io/install_setup/configuration/lenses-config.html) and
mount them under `/mnt/settings` and `/mnt/secrets` respectively —i.e
`/mnt/settings/lenses.conf` and `/mnt/secrets/security.conf`. You can set either
one or both together. Please for `lenses.conf` omit the settings
`lenses.secret.file` and `lenses.license.file`. If by any chance you set them,
you have to make sure lenses can find the files described in these settings.

### The license file

Lenses require a license file in order to start. It may be passed to the
container via three methods:

- As a file, mounted at /license.json or /mnt/secrets/license.json (e.g `-v
  /path/to/license.json:/license.json`)
- As the contents of the environment variable LICENSE (e.g `-e LICENSE="$(cat license.json)"`)
- As a downloadable URL via LICENSE_URL (e.g `-e LICENSE_URL="https://license.url/"`)

---

For more information, please visit
our [documentation](https://docs.lenses.io/). Enterprise customers may use the
support channels made available to them. Developer Edition users are encouraged
to visit our [slack community](https://launchpass.com/landoop-community). We are
always happy to help and hear from you.

With respect,

The Lenses Team.

---

Copyright 2017-2019, Lenses.io Ltd
