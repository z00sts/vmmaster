# coding: utf-8
import os
import time
import logging

from functools import wraps
from functools import partial
from uuid import uuid4
from threading import Thread

from core.sessions import RequestHelper
from vmpool import VirtualMachine

from core.exceptions import CreationException
from core.config import config
from core.utils import network_utils, exception_handler
from core.clients.docker_client import DockerManageClient


log = logging.getLogger(__name__)


def threaded_wait(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        def thread_target():
            return func(self, *args, **kwargs)

        tr = Thread(target=thread_target, name=getattr(func, "__name__", None))
        tr.daemon = True
        tr.start()

    return wrapper


class Clone(VirtualMachine):
    def __init__(self, origin, prefix, pool):
        self.uuid = str(uuid4())[:8]
        self.prefix = '%s' % prefix
        self.origin = origin
        self.pool = pool
        name = "{platform}-clone-{prefix}-{uuid}".format(
            platform=origin.name, prefix=self.prefix, uuid=self.uuid)

        super(Clone, self).__init__(name=name, platform=origin.name)

    def __str__(self):
        return "{name}({ip})".format(name=self.name, ip=self.ip)

    def delete(self):
        raise NotImplementedError

    def create(self):
        raise NotImplementedError

    def rebuild(self):
        raise NotImplementedError

    def save_artifacts(self, session, artifacts):
        return self.pool.save_artifact(session, artifacts)

    def ping_vm(self, ports=config.PORTS):
        result = [False, False]
        timeout = config.PING_TIMEOUT
        start = time.time()

        log.info("Starting ping vm {clone}: {ip}:{port}".format(
            clone=self.name, ip=self.ip, port=ports))
        _ping = partial(network_utils.ping, self.ip)
        while time.time() - start < timeout:
            result = map(_ping, ports)
            if all(result):
                log.info(
                    "Successful ping for {clone} with {ip}:{ports}".format(
                        clone=self.name, ip=self.ip, ports=ports))
                break
            time.sleep(0.1)

        if not all(result):
            fails = [port for port, res in zip(ports, result) if res is False]
            log.info("Failed ping for {clone} with {ip}:{ports}".format(
                clone=self.name, ip=self.ip, ports=str(fails))
            )
            return False

        return True


class OpenstackClone(Clone):
    def __init__(self, origin, prefix, pool):
        super(OpenstackClone, self).__init__(origin, prefix, pool)
        self.platform = origin.short_name
        self.nova_client = self._get_nova_client()

    @staticmethod
    def _get_nova_client():
        from core.utils import openstack_utils
        return openstack_utils.nova_client()

    @property
    def network_id(self):
        return getattr(config, "OPENSTACK_NETWORK_ID")

    @staticmethod
    def set_userdata(file_path):
        if os.path.isfile(file_path):
            try:
                return open(file_path)
            except:
                log.exception("Userdata from %s wasn't applied" % file_path)

    def create(self):
        log.info(
            "Creating openstack clone of {} with image={}, "
            "flavor={}".format(self.name, self.image, self.flavor))

        kwargs = {
            'name': self.name,
            'image': self.image,
            'flavor': self.flavor,
            'nics': [{'net-id': self.network_id}],
            'meta': getattr(config, "OPENASTACK_VM_META_DATA", {}),
            'userdata': self.set_userdata(
                getattr(config, "OPENSTACK_VM_USERDATA_FILE_PATH", "userdata")
            )
        }
        if bool(config.OPENSTACK_ZONE_FOR_VM_CREATE):
            kwargs.update({'availability_zone': config.OPENSTACK_ZONE_FOR_VM_CREATE})

        self.nova_client.servers.create(**kwargs)
        self._wait_for_activated_service(self.get_ip)

    def _parse_ip_from_networks(self):
        server = self.get_vm(self.name)
        if not server:
            return

        try:
            addresses = server.networks.get(config.OPENSTACK_NETWORK_NAME, None)
        except Exception as e:
            log.exception("Vm {} does not have address block".format(self.name))
            return None

        if addresses is not None:
            ip = addresses[0]
            return ip
        return None

    def get_ip(self):
        if self.ip:
            return

        ip = self._parse_ip_from_networks()
        if ip:
            self.ip = ip
            log.info("Got ip for {clone}: {ip}".format(clone=self.name, ip=self.ip))

    @threaded_wait
    def _wait_for_activated_service(self, method=None):
        config_create_check_retry_count, config_create_check_pause = \
            config.VM_CREATE_CHECK_ATTEMPTS, config.VM_CREATE_CHECK_PAUSE
        create_check_retry = 1
        ping_retry = 1

        while not self.done:
            server = self.get_vm(self.name)
            if not server:
                log.error("VM %s has not been created." % self.name)
                self.delete(try_to_rebuild=False)
                break

            if self.is_spawning(server):
                log.info("Virtual Machine %s is spawning..." % self.name)

                if create_check_retry > config_create_check_retry_count:
                    p = config_create_check_retry_count * \
                        config_create_check_pause
                    log.info("VM %s creates more than %s seconds, "
                             "check this VM" % (self.name, p))

                create_check_retry += 1
                time.sleep(config_create_check_pause)

            elif self.is_created(server):
                if method is not None:
                    method()
                if self.ping_vm():
                    self.ready = True
                    break
                if ping_retry > config.VM_PING_RETRY_COUNT:
                    p = config.VM_PING_RETRY_COUNT * config.PING_TIMEOUT
                    log.info("VM %s pings more than %s seconds..." % (self.name, p))
                    self.delete(try_to_rebuild=True)
                    break
                ping_retry += 1

            elif self.is_broken(server):
                log.error("VM %s was errored. Rebuilding..." % server.name)
                self.rebuild()
                break
            else:
                log.warning("Something ugly happened {}".format(server.name))
                break
        else:
            log.debug("VM {} is done: stop threaded wait".format(self.name))

    @property
    def image(self):
        return self.nova_client.glance.find_image(self.origin.name)

    @property
    def flavor(self):
        return self.nova_client.flavors.find(name=self.origin.flavor_name)

    @staticmethod
    def is_created(server):
        if server.status.lower() == 'active':
            if getattr(server, 'addresses', None) is not None:
                return True

        return False

    @staticmethod
    def is_spawning(server):
        return server.status.lower() in ('build', 'rebuild')

    @staticmethod
    def is_broken(server):
        return server.status.lower() == 'error'

    def get_vm(self, server_name):
        try:
            server = self.nova_client.servers.find(name=server_name)
            return server if server else None
        except:
            log.exception("VM %s does not exist" % server_name)
            return None

    def delete(self, try_to_rebuild=True):
        if try_to_rebuild and self.is_preloaded():
            self.rebuild()
            return

        self.ready = False
        self.pool.remove_vm(self)
        server = self.get_vm(self.name)
        if server:
            try:
                server.delete()
            except:
                log.exception("Delete vm %s was FAILED." % self.name)

        log.info("Deleted openstack clone: {0}".format(self.name))
        VirtualMachine.delete(self)

    def rebuild(self):
        log.info("Rebuilding openstack {clone}".format(clone=self.name))
        self.ready = False

        if self.is_preloaded():
            self.pool.remove_vm(self)
            self.pool.pool.append(self)

        server = self.get_vm(self.name)
        if server:
            try:
                server.rebuild(self.image)
                self._wait_for_activated_service(
                    lambda: log.info(
                        "Rebuild vm %s was successful" % self.name
                    )
                )
            except:
                log.exception("Rebuild vm %s was FAILED." % self.name)
                self.delete(try_to_rebuild=False)


def clone_watcher(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self.update()
        for value in func(self, *args, **kwargs):
            time.sleep(0.1)
        return value
    return wrapper


class DockerClone(Clone):
    __container = None

    def __init__(self, origin, prefix, pool):
        super(DockerClone, self).__init__(origin, prefix, pool)
        self.pool = pool
        self.platform = origin.name
        self.name = "{}-{}".format(self.platform, self.prefix)
        self.client = DockerManageClient()

    def __str__(self):
        return self.name

    def get_bind_port(self, original_port):
        if self.__container:
            return self.__container.ports.get(original_port)

    @property
    def vnc_port(self):
        return self.get_bind_port(config.VNC_PORT)

    @property
    def selenium_port(self):
        return self.get_bind_port(config.SELENIUM_PORT)

    @property
    def agent_port(self):
        return self.get_bind_port(config.VMMASTER_AGENT_PORT)

    @property
    def ports(self):
        if self.__container:
            return self.__container.ports.values()

    def update(self):
        self.__container = self.get_container()

    def get_container(self):
        if self.__container:
            return self.client.get_container(self.__container.id)

    def connect_network(self):
        if self.__container:
            self.pool.network.connect_container(self.__container.id)

    @exception_handler()
    def disconnect_network(self):
        if self.__container:
            self.pool.network.disconnect_container(self.__container.id)

    @property
    def status(self):
        if self.__container:
            return self.__container.status.lower()

    @property
    def is_spawning(self):
        return self.status in ('restarting', 'removing')

    @property
    def is_created(self):
        return self.status in ('created', 'running')

    @property
    def is_broken(self):
        return self.status in ('paused', 'exited', 'dead')

    @clone_watcher
    def create(self):
        self.__container = self.client.run_container(image=self.platform)
        self.name += "-{}".format(self.__container.short_id)
        if not config.BIND_LOCALHOST_PORTS:
            self.pool.network.connect_container(self.__container.id)

        log.info("Preparing {}...".format(self.name))
        for ready in self._wait_for_activated_service():
            self.ready = ready
            yield ready
        log.info("Creation {} was successful".format(self.name))

    @property
    def selenium_is_ready(self):
        for status, headers, body in network_utils.make_request(
            self.ip,
            self.selenium_port,
            RequestHelper("GET", "/wd/hub/status")
        ):
            pass
        return status == 200

    def _wait_for_activated_service(self):
        ready = None
        ping_retry = 1

        while not ready:
            yield ready
            self.update()
            if self.is_spawning:
                log.info("Container {} is spawning...".format(self.name))

            elif self.is_created:
                if not self.__container.ip:
                    log.info("Waiting ip for {}".format(self.name))
                    continue
                self.ip = self.__container.ip
                if self.ping_vm(ports=self.ports) and self.selenium_is_ready:
                    ready = True
                    break
                if ping_retry > config.VM_PING_RETRY_COUNT:
                    p = config.VM_PING_RETRY_COUNT * config.PING_TIMEOUT
                    log.info("Container {} pings more than {} seconds...".format(self.name, p))
                    self.delete(try_to_rebuild=True)
                    break
                ping_retry += 1

            elif self.is_broken or not self.status:
                raise CreationException("Container {} has not been created.".format(self.name))
            else:
                log.warning("Unknown status {} for container {}".format(self.status, self.name))
        yield ready

    @clone_watcher
    def delete(self, try_to_rebuild=False):
        if try_to_rebuild and self.is_preloaded():
            self.rebuild()

        self.ready = False
        try:
            self.pool.remove_vm(self)
            if not config.BIND_LOCALHOST_PORTS:
                self.pool.network.disconnect_container(self.__container.id)
            self.__container.stop()
            self.__container.remove()
        except:
            log.exception("Delete {} was failed".format(self.name))
        yield True

    @clone_watcher
    def rebuild(self):
        log.info("Rebuilding container {}".format(self.name))
        self.ready = False
        ready = None

        try:
            if self.is_preloaded():
                self.pool.remove_vm(self)
                self.pool.pool.append(self)

            self.__container.restart()
            for ready in self._wait_for_activated_service():
                yield ready

            log.info("Rebuild {} was successful".format(self.name))
        except:
            log.exception("Rebuild {} was failed".format(self.name))
            self.delete()
        yield ready
