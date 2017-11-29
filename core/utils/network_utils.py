import time
import logging
import netifaces
import requests
from core import constants, config
from core.exceptions import RequestException, RequestTimeoutException
from . import system_utils
import socket


log = logging.getLogger(__name__)


class RequestHelper(object):
    method = None
    url = None
    headers = None
    data = None

    def __init__(self, method, url="/", headers=None, data=""):
        _headers = {}
        if headers:
            for key, value in headers.items():
                if value:
                    _headers[key] = value
        _headers["Content-Length"] = str(len(data))
        self.headers = _headers
        self.method = method
        self.url = url
        self.data = data

    def __repr__(self):
        return "<RequestHelper method:%s url:%s headers:%s body:%s>" % (
            self.method, self.url, self.headers, self.data)


def get_interface_subnet(inteface):
    ip = netifaces.ifaddresses(inteface)[2][0]["addr"]
    split_ip = ip.split(".")
    split_ip[-1] = "0"
    ip = ".".join(split_ip)
    return ip + "/24"


def nmap_ping_scan(subnet):
    return system_utils.run_command(["nmap", "-sP", "-T4", subnet])


def arp_numeric():
    return system_utils.run_command(["arp", "--numeric"])


def get_ip_by_mac(mac):
    subnet = get_interface_subnet("br0")
    nmap_ping_scan(subnet)
    code, output = arp_numeric()
    split_output = output.split("\n")

    for line in split_output:
        if mac in line:
            break

    if line == "":
        return None

    return line.split(" ")[0]


def get_socket(host, port):
    s = None

    addr_info = socket.getaddrinfo(
        host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
    )
    for af, socktype, proto, canonname, sa in addr_info:
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error:
            s = None
            continue
        try:
            s = socket.create_connection((host, port), timeout=0.1)
        except socket.error:
            s.close()
            s = None
            continue
        break

    return s


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ping(ip, port):
    try:
        s = get_socket(ip, int(port))
    except Exception:
        return False
    if s:
        s.close()
        return True

    return False


def make_request(
        endpoint_ip, port, request,
        timeout=getattr(config, "REQUEST_TIMEOUT", constants.REQUEST_TIMEOUT),
        attempts=getattr(config, "MAKE_REQUEST_ATTEMPTS_AMOUNT", constants.MAKE_REQUEST_ATTEMPTS_AMOUNT)
):
    """
    Make http request to some port in session and return the response.
    """
    url = "http://{}:{}{}".format(endpoint_ip, port, request.url)

    if request.headers.get("Host"):
        del request.headers['Host']

    try:
        for attempt, sleep_time in map(lambda x: (x, constants.REQUEST_SLEEP_BASE_TIME * x), range(1, attempts + 1)):
            yield None, None, None
            log.info("Attempt {}. Making request {} with timeout {} sec.".format(attempt, url, timeout))
            try:
                response = requests.request(
                    method=request.method,
                    url=url,
                    headers=request.headers,
                    data=request.data,
                    timeout=timeout
                )
                yield response.status_code, response.headers, response.content
            except:
                if attempt < attempts:
                    log.info("Waiting {} seconds before next attempt to request {}".format(sleep_time, url))
                    time.sleep(sleep_time)
                    continue
                raise
    except requests.Timeout as e:
        raise RequestTimeoutException(
            "No response for '{}' in {} sec. Original: {}".format(url, timeout, e)
        )
    except Exception as e:
        raise RequestException("Error for '{}'. Original: {}".format(url, e))
