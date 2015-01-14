# coding: utf-8
import time
from threading import Thread
from collections import defaultdict
from uuid import uuid4

from .clone import Clone

from ..exceptions import CreationException
from ..config import config
from ..logger import log


class VirtualMachinesPool(object):
    pool = list()
    using = list()

    def __str__(self):
        return str(self.pool)

    @classmethod
    def remove_vm(cls, vm):
        cls.using.remove(vm)

    @classmethod
    def free(cls):
        log.info("deleting using machines")
        for vm in list(cls.using):
            cls.using.remove(vm)
            vm.delete()
        log.info("deleting pool")
        for vm in list(cls.pool):
            cls.pool.remove(vm)
            vm.delete()

    @classmethod
    def count(cls):
        return len(cls.pool) + len(cls.using)

    @classmethod
    def can_produce(cls):
        return config.MAX_VM_COUNT - cls.count()

    @classmethod
    def has(cls, platform):
        for vm in cls.pool:
            if vm.platform == platform and vm.ready:
                return True

        return False

    @classmethod
    def get(cls, platform):
        for vm in sorted(cls.pool, key=lambda v: v.creation_time):
            if vm.platform == platform and vm.ready:
                cls.pool.remove(vm)
                cls.using.append(vm)
                return vm

    @classmethod
    def count_virtual_machines(cls, it):
        result = defaultdict(int)
        for vm in it:
            result[vm.platform] += 1

        return result

    @classmethod
    def pooled_virtual_machines(cls):
        return cls.count_virtual_machines(cls.pool)

    @classmethod
    def using_virtual_machines(cls):
        return cls.count_virtual_machines(cls.using)

    @classmethod
    def add(cls, origin_name, prefix=None):
        if not cls.can_produce():
            raise CreationException("maximum count of virtual machines already running")

        if prefix is None:
            prefix = "ondemand-%s" % uuid4()
        from ..platforms import Platforms
        clone = Clone(Platforms.get(origin_name), prefix)
        cls.using.append(clone)

        try:
            clone.create()
        except Exception:
            clone.delete()
            cls.using.remove(clone)
            raise

        return clone

    @classmethod
    def return_vm(cls, vm):
        cls.using.remove(vm)
        cls.pool.append(vm)

    @property
    def info(self):
        return {
            "pool": self.pooled_virtual_machines(),
            "can_produce": self.can_produce()
        }


class VirtualMachinesPoolPreloader(Thread):
    def __init__(self, pool):
        Thread.__init__(self)
        self.running = True
        self.daemon = True
        self.pool = pool

    def run(self):
        while self.running:
            if self.pool.can_produce():
                platform = self.need_load()
                if platform is not None:
                    self.pool.add(platform, "preloaded-%s" % uuid4())

            time.sleep(1)

    def need_load(self):
        already_have = self.pool.pooled_virtual_machines()
        for platform, need in config.PRELOADED.iteritems():
            have = already_have.get(platform, 0)
            if need > have:
                return platform

    def stop(self):
        self.running = False
        self.join()
        log.info("Preloader stopped")


pool = VirtualMachinesPool()