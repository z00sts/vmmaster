import os


class Config(object):
    BASEDIR = os.path.dirname(os.path.realpath(__file__))
    PORT = 9001

    # PostgreSQL dbname
    DATABASE = "postgresql+psycopg2://vmmaster:vmmaster@localhost/testdb"

    CLONES_DIR = BASEDIR + "/vmmaster/clones"
    ORIGINS_DIR = BASEDIR + "/vmmaster/origins"
    SESSION_DIR = BASEDIR + "/vmmaster/session"

    # screenshots
    SCREENSHOTS_DIR = BASEDIR + "/vmmaster/screenshots"
    SCREENSHOTS_DAYS = 7

    # logging
    LOG_DIR = BASEDIR + "/logs"
    LOG_SIZE = 5242880

    # kvm
    USE_KVM = True
    KVM_MAX_VM_COUNT = 2
    KVM_PRELOADED = {
        # "ubuntu-14.04-x64": 1
    }

    # openstack
    USE_OPENSTACK = False
    OPENSTACK_MAX_VM_COUNT = 2
    OPENSTACK_PRELOADED = {
        # "ubuntu-14.04-x64": 1
    }

    OPENSTACK_AUTH_URL = "localhost"
    OPENSTACK_PORT = 5000
    OPENSTACK_CLIENT_VERSION = "v2.0"
    OPENSTACK_USERNAME = "user"
    OPENSTACK_PASSWORD = "password"
    OPENSTACK_TENANT_NAME = "test"
    OPENSTACK_TENANT_ID = ""
    OPENSTACK_ZONE_FOR_VM_CREATE = ""
    OPENSTACK_PLATFORM_NAME_PREFIX = "origin-"
    OPENSTACK_PING_RETRY_COUNT = 3
    OPENASTACK_VM_META_DATA = {
        'admin_pass': 'testPassw0rd.'
    }

    VM_CHECK = False
    VM_CHECK_FREQUENCY = 1800
    VM_CREATE_CHECK_PAUSE = 5
    VM_CREATE_CHECK_ATTEMPTS = 1000
    PRELOADER_FREQUENCY = 3
    SESSION_TIMEOUT = 360
    PING_TIMEOUT = 180

    # vm pool
    GET_VM_TIMEOUT = 180
    VM_POOL_PORT = 9999
    VM_POOL_HOST = 'localhost'

    # additional logging
    # sending logs into graylog2 or logstash (Graylog Extended Log Format, GELF)
    # GRAYLOG = ('logserver', 12201)

    # graphite
    # GRAPHITE = ('graphite', 2003)

    # selenium
    SELENIUM_PORT = 4455
    VMMASTER_AGENT_PORT = 9000

    LOG_LEVEL = "INFO"