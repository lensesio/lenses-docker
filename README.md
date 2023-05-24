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
engineering talk is on [Discourse](https://ask.lenses.io) and [Slack](https://launchpass.com/landoop-community)

## The Docker Image

**Please check out the
[docker image documentation at docs.lenses.io](https://docs.lenses.io/current/installation/getting-started/docker/)
for the most recent docs and the complete set of features, settings and tweak
knobs.**


This image is aimed for our enterprise clients, though anyone with a free
developer license may use it. Visit
our [download page](https://lenses.io/downloads/) to get a free developer
license or an enterprise trial.  Only Lenses is included in this docker. Our
development environment image, which additionally includes Kafka, Connect,
Schema Registry and our open-source Stream Reactor collection of connectors can
be found as `lensesio/box`.

This image has to be run alongside a Kafka cluster.


## How to run

In the current iteration `lensesio/lenses` uses environment variables as the
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
    image: lensesio/lenses
    environment:
      LENSES_PORT: 9991

      # # Users are managed within Lenses. Here you can change the superuser username:
      # LENSES_SECURITY_USER: admin
      # # Users are managed within Lenses. Here you can change the superuser password:
      # LENSES_SECURITY_PASSWORD: admin
    ports:
      - 9991:9991
      - 9102:9102
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
[documentation](https://docs.lenses.io/current/installation/configuration/) and
mount them under `/mnt/settings` and `/mnt/secrets` respectively —i.e
`/mnt/settings/lenses.conf` and `/mnt/secrets/security.conf`. You can set either
one or both together. Please for `lenses.conf` omit the settings
`lenses.secret.file`. If by any chance you set them,
you have to make sure lenses can find the files described in these settings.

## How to build

If you want to build the image yourself, you can just run:

```bash
docker build -t lensesiolocal/lenses .
```

If you are on an older version of Docker which does not support multi-arch
builds, you can emulate a multi-arch build via args:

```bash
docker build \
  --build-arg TARGETOS=linux --build-arg TARGETARCH=amd64 \
  -t lensesiolocal/lenses .
```


---

For more information, please visit
our [documentation](https://docs.lenses.io/). Enterprise customers may use the
support channels made available to them. Developer Edition users are encouraged
to visit our [slack community](https://launchpass.com/landoop-community). We are
always happy to help and hear from you.

With respect,

The Lenses Team.

---

Copyright 2017-2023, Lenses.io Ltd
