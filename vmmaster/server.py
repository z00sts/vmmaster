from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint

from .core.clone_factory import CloneFactory
from .core.network.sessions import Sessions
from .core.network.network import Network
from .core.logger import log
from .core.server.proxy_factory import ProxyFactory


class VMMasterServer(object):
    def __init__(self, server_address):
        # creating network
        self.network = Network()
        self.clone_factory = CloneFactory()
        self.sessions = Sessions()

        # server props
        self.server_address = server_address
        # self.handler = self.handleRequestsUsing(self.clone_factory, self.sessions)

    def __del__(self):
        self.clone_factory.delete()
        self.network.delete()

    def run(self):
        log.info('Starting server on %s ...' % str(self.server_address))
        endpoint_clones = TCP4ServerEndpoint(reactor, 9000)
        # endpoint_api = TCP4ServerEndpoint(reactor, 9001)
        endpoint_clones.listen(ProxyFactory(self.clone_factory, self.sessions))
        # endpoint_api.listen(apiServer)

        reactor.run()
        log.info("shutting down...")
        del self