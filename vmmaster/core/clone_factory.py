from threading import Timer
import time

from vmmaster.core.clone import Clone
from vmmaster.core.connection import Virsh
from vmmaster.core.config import config
from vmmaster.core.logger import log


class PlatformException(Exception):
    pass


class ClonesException(Exception):
    pass


class TimeoutException(Exception):
    pass


class CloneShutdownTimer(object):
    def __init__(self, timeout, callback, *args):
        self.__timeout = timeout
        self.__callback = callback
        self.__args = args
        self.__start_time = 0
        self.__timer = Timer(self.__timeout, self.__callback, self.__args)

    def __del__(self):
        log.debug("CloneShutdownTimer __del__")
        self.__timer.cancel()
        del self.__timer

    def start(self):
        self.__timer.start()
        self.__start_time = time.time()

    def restart(self):
        self.__timer.cancel()
        del self.__timer
        self.__timer = Timer(self.__timeout, self.__callback, self.__args)
        self.__timer.start()

    def stop(self):
        self.__timer.cancel()

    def time_elapsed(self):
        return time.time() - self.__start_time


class CloneList(object):
    def __init__(self):
        self.list = dict()
        conn = Virsh()

        self.__clone_numbers = [i for i in reversed(range(0, config.MAX_CLONE_COUNT))]

        for platform in conn.listDefinedDomains():
            self.list[platform] = []

        log.debug("starting with " + str(self.list))

    def _check_platform(self, platform):
        if platform not in self.list:
            raise PlatformException("no such a platform")

    def _check_clone_count(self):
        print len(self.__clone_numbers)
        if len(self.__clone_numbers) == 0:
            raise ClonesException("maximum clones count already running")

    def _check_clone(self, clone):
        self._check_platform(clone.platform)
        self._check_clone_count()

    def add_clone(self, clone):
        self.list[clone.platform].append(clone)

    def remove_clone(self, clone):
        self.list[clone.platform].remove(clone)
        self.add_free_clone_number(clone.number)

    def get_clones(self, platform):
        return self.list[platform]

    def get_all_clones(self):
        clones = []
        for platform in self.get_platforms():
            clones += self.get_clones(platform)

        return clones

    @property
    def total_count(self):
        return len(self.get_all_clones())

    def clones_count(self, platform):
        return len(self.list[platform])

    def get_platforms(self):
        return self.list

    def get_free_clone_number(self, platform):
        self._check_platform(platform)
        self._check_clone_count()
        self.list[platform]
        # clone_numbers = [clone.number for clone in self.list[platform]]
        clone_numbers = self.__clone_numbers
        return clone_numbers.pop()

    def add_free_clone_number(self, number):
        self.__clone_numbers.append(number)


class CloneFactory(object):
    def __init__(self):
        log.info("initializing clone factory")
        self.clone_list = CloneList()

    def delete(self):
        log.info("deleting clone factory")
        running_clones = self.clone_list.get_all_clones()

        for clone in running_clones:
            self.utilize_clone(clone)

        del self

    def create_clone(self, platform):
        clone = Clone(self.clone_list.get_free_clone_number(platform), platform)
        self.clone_list.add_clone(clone)

        try:
            clone = clone.create()
        except Exception, e:
            self.utilize_clone(clone)
            raise e

        clone.set_timer(CloneShutdownTimer(config.CLONE_TIMEOUT, self.utilize_clone, clone, True))
        clone.get_timer().start()
        return clone

    def utilize_clone(self, clone, timeouted=False):
        if timeouted:
            log.warning("TIMEOUT {clone}".format(clone=clone.name))
        self.clone_list.remove_clone(clone)
        clone.delete()
        if timeouted:
            raise TimeoutException("clone timed out")
        return