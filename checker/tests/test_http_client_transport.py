import logging
import socketserver
import sys
import threading
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


try:
    import enochecker3  # noqa: F401
except ModuleNotFoundError:
    enochecker3 = types.ModuleType("enochecker3")
    enochecker3_utils = types.ModuleType("enochecker3.utils")

    class CheckerException(Exception):
        pass

    class Enochecker:
        def __init__(self, *_args, **_kwargs):
            self.app = None

        def _decorator(self, *_args, **_kwargs):
            def decorate(func):
                return func

            return decorate

        putflag = getflag = putnoise = getnoise = havoc = exploit = _decorator

    class ChainDB:
        pass

    class FlagSearcher:
        pass

    for name in (
        "ExploitCheckerTaskMessage",
        "GetflagCheckerTaskMessage",
        "GetnoiseCheckerTaskMessage",
        "HavocCheckerTaskMessage",
        "PutflagCheckerTaskMessage",
        "PutnoiseCheckerTaskMessage",
    ):
        setattr(enochecker3, name, type(name, (), {}))

    enochecker3.ChainDB = ChainDB
    enochecker3.Enochecker = Enochecker
    enochecker3.FlagSearcher = FlagSearcher
    enochecker3.MumbleException = type("MumbleException", (CheckerException,), {})
    enochecker3.OfflineException = type("OfflineException", (CheckerException,), {})
    enochecker3_utils.assert_equals = lambda *args, **kwargs: None
    enochecker3_utils.assert_in = lambda *args, **kwargs: None
    sys.modules["enochecker3"] = enochecker3
    sys.modules["enochecker3.utils"] = enochecker3_utils

from checker import HttpClient
from enochecker3 import OfflineException


class RawResponseServer(socketserver.TCPServer):
    allow_reuse_address = True


class RawResponseHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(4096)
        self.request.sendall(self.server.response)


def request_against(response: bytes, call):
    with RawResponseServer(("127.0.0.1", 0), RawResponseHandler) as server:
        server.response = response
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        logger = logging.LoggerAdapter(logging.getLogger("test"), {})
        client = HttpClient(f"http://127.0.0.1:{server.server_address[1]}", logger)
        try:
            return call(client)
        finally:
            thread.join(timeout=2)


class HttpClientTransportTests(unittest.TestCase):
    def test_successful_malformed_chunked_response_is_offline(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"\x00\x00\x00\x00\x00\r\n"
        )

        with self.assertRaises(OfflineException):
            request_against(response, lambda client: client._request_json_sync("GET", "/", None, None))

    def test_http_error_malformed_chunked_body_keeps_status(self) -> None:
        response = (
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"\x00\x00\x00\x00\x00\r\n"
        )

        status, data = request_against(
            response,
            lambda client: client._request_json_sync("GET", "/missing", None, None),
        )

        self.assertEqual(status, 404)
        self.assertIsNone(data)


if __name__ == "__main__":
    unittest.main()
