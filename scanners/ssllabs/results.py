from dataclasses import dataclass
from typing import Any, List, Optional, TypeVar, Callable, Type, cast
from enum import Enum


class SSLCSC(Enum):
    SSLCSC_STATUS_FAILED = -1
    SSLCSC_STATUS_UNKNOWN = 0
    SSLCSC_STATUS_NOT_VULNERABLE = 1
    SSLCSC_STATUS_POSSIBLE_VULNERABLE = 2
    SSLCSC_STATUS_VULNERABLE = 3


class LUCKY_MINUS(Enum):
    LUCKY_MINUS_STATUS_FAILED = -1
    LUCKY_MINUS_STATUS_UNKNOWN = 0
    LUCKY_MINUS_STATUS_NOT_VULNERABLE = 1
    LUCKY_MINUS_STATUS_VULNERABLE = 2


class TICKETBLEED(Enum):
    TICKETBLEED_STATUS_FAILED = -1
    TICKETBLEED_STATUS_UNKNOWN = 0
    TICKETBLEED_STATUS_NOT_VULNERABLE = 1
    TICKETBLEED_STATUS_VULNERABLE = 2


class BLEICHENBACHER(Enum):
    BLEICHENBACHER_STATUS_FAILED = -1
    BLEICHENBACHER_STATUS_UNKNOWN = 0
    BLEICHENBACHER_STATUS_NOT_VULNERABLE = 1
    BLEICHENBACHER_STATUS_VULNERABLE_WEAK = 2
    BLEICHENBACHER_STATUS_VULNERABLE_STRONG = 3
    BLEICHENBACHER_STATUS_INCONSISTENT_RESULTS = 4


class POODLE_TLS(Enum):
    POODLE_STATUS_TIMEOUT = -3
    POODLE_STATUS_TLS_NOT_SUPPORTED = -2
    POODLE_STATUS_FAILED = -1
    POODLE_STATUS_UNKNOWN = 0
    POODLE_STATUS_NOT_VULNERABLE = 1
    POODLE_STATUS_VULNERABLE = 2


class REVOCATION(Enum):
    REVOCATION_STATUS_NOT_CHECKED = 0
    REVOCATION_STATUS_REVOKED = 1
    REVOCATION_STATUS_NOT_REVOKED = 2
    REVOCATION_STATUS_REVOCATION_CHECK_ERROR = 3
    REVOCATION_STATUS_NO_REVOCATION_INFO = 4
    REVOCATION_STATUS_INTERNAL_INFO = 5


class HSTS(Enum):
    HSTS_STATUS_UNKNOWN = "unknown"
    HSTS_STATUS_ABSENT = "absent"
    HSTS_STATUS_PRESENT = "present"
    HSTS_STATUS_INVALID = "invalid"
    HSTS_STATUS_DISABLED = "disabled"
    HSTS_STATUS_ERROR = "error"


class HPKP(Enum):
    HPKP_STATUS_UNKNOWN = "unknown"
    HPKP_STATUS_ABSENT = "absent"
    HPKP_STATUS_INVALID = "invalid"
    HPKP_STATUS_DISABLED = "disabled"
    HPKP_STATUS_INCOMPLETE = "incomplete"
    HPKP_STATUS_VALID = "valid"
    HPKP_STATUS_ERROR = "error"


class SPKP(Enum):
    SPKP_STATUS_UNKNOWN = "unknown"
    SPKP_STATUS_ABSENT = "absent"
    SPKP_STATUS_INVALID = "invalid"
    SPKP_STATUS_INCOMPLETE = "incomplete"
    SPKP_STATUS_PARTIAL = "partial"
    SPKP_STATUS_FORBIDDEN = "forbidden"
    SPKP_STATUS_VALID = "valid"


class DROWN(Enum):
    DROWN_STATUS_ERROR = "error"
    DROWN_STATUS_UNKNOWN = "unknown"
    DROWN_STATUS_NOT_CHECKED = "not_checked"
    DROWN_STATUS_NOT_CHECKED_SAME_HOST = "not_checked_same_host"
    DROWN_STATUS_HANDSHAKE_FAILURE = "handshake_failure"
    DROWN_STATUS_SSLV2 = "sslv2"
    DROWN_STATUS_KEY_MATCH = "key_match"
    DROWN_STATUS_HOSTNAME_MATCH = "hostname_match"


class ProtocolVersion(Enum):
    PROTOCOL_SSL2 = 512
    PROTOCOL_SSL3 = 768
    PROTOCOL_TLS10 = 769
    PROTOCOL_TLS11 = 770
    PROTOCOL_TLS12 = 771
    PROTOCOL_TLS13 = 772


T = TypeVar("T")


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def is_type(t: Type[T], x: Any) -> T:
    assert isinstance(x, t)
    return x


@dataclass
class CaaRecord:
    tag: str
    value: str
    flags: int

    @staticmethod
    def from_dict(obj: Any) -> 'CaaRecord':
        assert isinstance(obj, dict)
        tag = from_str(obj.get("tag"))
        value = from_str(obj.get("value"))
        flags = from_int(obj.get("flags"))
        return CaaRecord(tag, value, flags)

    def to_dict(self) -> dict:
        result: dict = {}
        result["tag"] = from_str(self.tag)
        result["value"] = from_str(self.value)
        result["flags"] = from_int(self.flags)
        return result


@dataclass
class CaaPolicy:
    policy_hostname: str
    caa_records: List[CaaRecord]

    @staticmethod
    def from_dict(obj: Any) -> 'CaaPolicy':
        assert isinstance(obj, dict)
        policy_hostname = from_str(obj.get("policyHostname"))
        caa_records = from_list(CaaRecord.from_dict, obj.get("caaRecords"))
        return CaaPolicy(policy_hostname, caa_records)

    def to_dict(self) -> dict:
        result: dict = {}
        result["policyHostname"] = from_str(self.policy_hostname)
        result["caaRecords"] = from_list(lambda x: to_class(CaaRecord, x), self.caa_records)
        return result


@dataclass
class CERT:
    id: str
    subject: str
    serial_number: str
    common_names: List[str]
    not_before: int
    not_after: int
    issuer_subject: str
    sig_alg: str
    revocation_info: int
    revocation_status: int
    crl_revocation_status: int
    ocsp_revocation_status: int
    must_staple: bool
    sgc: int
    issues: int
    sct: bool
    sha1_hash: str
    sha256_hash: str
    pin_sha256: str
    key_alg: str
    key_size: int
    key_strength: int
    raw: str
    alt_names: Optional[List[str]] = None
    ocsp_ur_is: Optional[List[str]] = None
    dns_caa: Optional[bool] = None
    caa_policy: Optional[CaaPolicy] = None
    key_known_debian_insecure: Optional[bool] = None
    crl_ur_is: Optional[List[str]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CERT':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        subject = from_str(obj.get("subject"))
        serial_number = from_str(obj.get("serialNumber"))
        common_names = from_list(from_str, obj.get("commonNames"))
        not_before = from_int(obj.get("notBefore"))
        not_after = from_int(obj.get("notAfter"))
        issuer_subject = from_str(obj.get("issuerSubject"))
        sig_alg = from_str(obj.get("sigAlg"))
        revocation_info = from_int(obj.get("revocationInfo"))
        revocation_status = from_int(obj.get("revocationStatus"))
        crl_revocation_status = from_int(obj.get("crlRevocationStatus"))
        ocsp_revocation_status = from_int(obj.get("ocspRevocationStatus"))
        must_staple = from_bool(obj.get("mustStaple"))
        sgc = from_int(obj.get("sgc"))
        issues = from_int(obj.get("issues"))
        sct = from_bool(obj.get("sct"))
        sha1_hash = from_str(obj.get("sha1Hash"))
        sha256_hash = from_str(obj.get("sha256Hash"))
        pin_sha256 = from_str(obj.get("pinSha256"))
        key_alg = from_str(obj.get("keyAlg"))
        key_size = from_int(obj.get("keySize"))
        key_strength = from_int(obj.get("keyStrength"))
        raw = from_str(obj.get("raw"))
        alt_names = from_union([lambda x: from_list(from_str, x), from_none], obj.get("altNames"))
        ocsp_ur_is = from_union([lambda x: from_list(from_str, x), from_none], obj.get("ocspURIs"))
        dns_caa = from_union([from_bool, from_none], obj.get("dnsCaa"))
        caa_policy = from_union([CaaPolicy.from_dict, from_none], obj.get("caaPolicy"))
        key_known_debian_insecure = from_union([from_bool, from_none], obj.get("keyKnownDebianInsecure"))
        crl_ur_is = from_union([lambda x: from_list(from_str, x), from_none], obj.get("crlURIs"))
        return CERT(id, subject, serial_number, common_names, not_before, not_after, issuer_subject, sig_alg,
                    revocation_info, revocation_status, crl_revocation_status, ocsp_revocation_status, must_staple, sgc,
                    issues, sct, sha1_hash, sha256_hash, pin_sha256, key_alg, key_size, key_strength, raw, alt_names,
                    ocsp_ur_is, dns_caa, caa_policy, key_known_debian_insecure, crl_ur_is)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["subject"] = from_str(self.subject)
        result["serialNumber"] = from_str(self.serial_number)
        result["commonNames"] = from_list(from_str, self.common_names)
        result["notBefore"] = from_int(self.not_before)
        result["notAfter"] = from_int(self.not_after)
        result["issuerSubject"] = from_str(self.issuer_subject)
        result["sigAlg"] = from_str(self.sig_alg)
        result["revocationInfo"] = from_int(self.revocation_info)
        result["revocationStatus"] = from_int(self.revocation_status)
        result["crlRevocationStatus"] = from_int(self.crl_revocation_status)
        result["ocspRevocationStatus"] = from_int(self.ocsp_revocation_status)
        result["mustStaple"] = from_bool(self.must_staple)
        result["sgc"] = from_int(self.sgc)
        result["issues"] = from_int(self.issues)
        result["sct"] = from_bool(self.sct)
        result["sha1Hash"] = from_str(self.sha1_hash)
        result["sha256Hash"] = from_str(self.sha256_hash)
        result["pinSha256"] = from_str(self.pin_sha256)
        result["keyAlg"] = from_str(self.key_alg)
        result["keySize"] = from_int(self.key_size)
        result["keyStrength"] = from_int(self.key_strength)
        result["raw"] = from_str(self.raw)
        result["altNames"] = from_union([lambda x: from_list(from_str, x), from_none], self.alt_names)
        result["ocspURIs"] = from_union([lambda x: from_list(from_str, x), from_none], self.ocsp_ur_is)
        result["dnsCaa"] = from_union([from_bool, from_none], self.dns_caa)
        result["caaPolicy"] = from_union([lambda x: to_class(CaaPolicy, x), from_none], self.caa_policy)
        result["keyKnownDebianInsecure"] = from_union([from_bool, from_none], self.key_known_debian_insecure)
        result["crlURIs"] = from_union([lambda x: from_list(from_str, x), from_none], self.crl_ur_is)
        return result


@dataclass
class Trust:
    root_store: str
    is_trusted: bool

    @staticmethod
    def from_dict(obj: Any) -> 'Trust':
        assert isinstance(obj, dict)
        root_store = from_str(obj.get("rootStore"))
        is_trusted = from_bool(obj.get("isTrusted"))
        return Trust(root_store, is_trusted)

    def to_dict(self) -> dict:
        result: dict = {}
        result["rootStore"] = from_str(self.root_store)
        result["isTrusted"] = from_bool(self.is_trusted)
        return result


@dataclass
class TrustPath:
    cert_ids: List[str]
    trust: List[Trust]

    @staticmethod
    def from_dict(obj: Any) -> 'TrustPath':
        assert isinstance(obj, dict)
        cert_ids = from_list(from_str, obj.get("certIds"))
        trust = from_list(Trust.from_dict, obj.get("trust"))
        return TrustPath(cert_ids, trust)

    def to_dict(self) -> dict:
        result: dict = {}
        result["certIds"] = from_list(from_str, self.cert_ids)
        result["trust"] = from_list(lambda x: to_class(Trust, x), self.trust)
        return result


@dataclass
class CERTChain:
    id: str
    cert_ids: List[str]
    trust_paths: List[TrustPath]
    issues: int
    no_sni: bool

    @staticmethod
    def from_dict(obj: Any) -> 'CERTChain':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        cert_ids = from_list(from_str, obj.get("certIds"))
        trust_paths = from_list(TrustPath.from_dict, obj.get("trustPaths"))
        issues = from_int(obj.get("issues"))
        no_sni = from_bool(obj.get("noSni"))
        return CERTChain(id, cert_ids, trust_paths, issues, no_sni)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["certIds"] = from_list(from_str, self.cert_ids)
        result["trustPaths"] = from_list(lambda x: to_class(TrustPath, x), self.trust_paths)
        result["issues"] = from_int(self.issues)
        result["noSni"] = from_bool(self.no_sni)
        return result


@dataclass
class HpkpPolicy:
    status: HPKP
    pins: List[Any]
    matched_pins: List[Any]
    directives: List[Any]

    @staticmethod
    def from_dict(obj: Any) -> 'HpkpPolicy':
        assert isinstance(obj, dict)
        status = from_str(obj.get("status"))
        pins = from_list(lambda x: x, obj.get("pins"))
        matched_pins = from_list(lambda x: x, obj.get("matchedPins"))
        directives = from_list(lambda x: x, obj.get("directives"))
        return HpkpPolicy(status, pins, matched_pins, directives)

    def to_dict(self) -> dict:
        result: dict = {}
        result["status"] = from_str(self.status)
        result["pins"] = from_list(lambda x: x, self.pins)
        result["matchedPins"] = from_list(lambda x: x, self.matched_pins)
        result["directives"] = from_list(lambda x: x, self.directives)
        return result


@dataclass
class Directives:
    max_age: Optional[int] = None
    includesubdomains: Optional[str] = None
    preload: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Directives':
        assert isinstance(obj, dict)
        max_age = from_union([from_none, lambda x: int(from_str(x))], obj.get("max-age"))
        includesubdomains = from_union([from_str, from_none], obj.get("includesubdomains"))
        preload = from_union([from_str, from_none], obj.get("preload"))
        return Directives(max_age, includesubdomains, preload)

    def to_dict(self) -> dict:
        result: dict = {}
        result["max-age"] = from_union([lambda x: from_none((lambda x: is_type(type(None), x))(x)),
                                        lambda x: from_str((lambda x: str((lambda x: is_type(int, x))(x)))(x))],
                                       self.max_age)
        result["includesubdomains"] = from_union([from_str, from_none], self.includesubdomains)
        result["preload"] = from_union([from_str, from_none], self.preload)
        return result


@dataclass
class HstsPolicy:
    long_max_age: int
    status: HSTS
    directives: Directives
    header: Optional[str] = None
    max_age: Optional[int] = None
    include_sub_domains: Optional[bool] = None
    preload: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'HstsPolicy':
        assert isinstance(obj, dict)
        long_max_age = from_int(obj.get("LONG_MAX_AGE"))
        status = from_str(obj.get("status"))
        directives = Directives.from_dict(obj.get("directives"))
        header = from_union([from_str, from_none], obj.get("header"))
        max_age = from_union([from_int, from_none], obj.get("maxAge"))
        include_sub_domains = from_union([from_bool, from_none], obj.get("includeSubDomains"))
        preload = from_union([from_bool, from_none], obj.get("preload"))
        return HstsPolicy(long_max_age, status, directives, header, max_age, include_sub_domains, preload)

    def to_dict(self) -> dict:
        result: dict = {}
        result["LONG_MAX_AGE"] = from_int(self.long_max_age)
        result["status"] = from_str(self.status)
        result["directives"] = to_class(Directives, self.directives)
        result["header"] = from_union([from_str, from_none], self.header)
        result["maxAge"] = from_union([from_int, from_none], self.max_age)
        result["includeSubDomains"] = from_union([from_bool, from_none], self.include_sub_domains)
        result["preload"] = from_union([from_bool, from_none], self.preload)
        return result


@dataclass
class HstsPreload:
    source: str
    hostname: str
    status: HSTS
    source_time: int

    @staticmethod
    def from_dict(obj: Any) -> 'HstsPreload':
        assert isinstance(obj, dict)
        source = from_str(obj.get("source"))
        hostname = from_str(obj.get("hostname"))
        status = from_str(obj.get("status"))
        source_time = from_int(obj.get("sourceTime"))
        return HstsPreload(source, hostname, status, source_time)

    def to_dict(self) -> dict:
        result: dict = {}
        result["source"] = from_str(self.source)
        result["hostname"] = from_str(self.hostname)
        result["status"] = from_str(self.status)
        result["sourceTime"] = from_int(self.source_time)
        return result


@dataclass
class ResponseHeader:
    name: str
    value: str

    @staticmethod
    def from_dict(obj: Any) -> 'ResponseHeader':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        value = from_str(obj.get("value"))
        return ResponseHeader(name, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["value"] = from_str(self.value)
        return result


@dataclass
class HTTPTransaction:
    request_url: str
    status_code: int
    request_line: str
    request_headers: List[str]
    response_line: str
    response_headers_raw: List[str]
    response_headers: List[ResponseHeader]
    fragile_server: bool

    @staticmethod
    def from_dict(obj: Any) -> 'HTTPTransaction':
        assert isinstance(obj, dict)
        request_url = from_str(obj.get("requestUrl"))
        status_code = from_int(obj.get("statusCode"))
        request_line = from_str(obj.get("requestLine"))
        request_headers = from_list(from_str, obj.get("requestHeaders"))
        response_line = from_str(obj.get("responseLine"))
        response_headers_raw = from_list(from_str, obj.get("responseHeadersRaw"))
        response_headers = from_list(ResponseHeader.from_dict, obj.get("responseHeaders"))
        fragile_server = from_bool(obj.get("fragileServer"))
        return HTTPTransaction(request_url, status_code, request_line, request_headers, response_line,
                               response_headers_raw, response_headers, fragile_server)

    def to_dict(self) -> dict:
        result: dict = {}
        result["requestUrl"] = from_str(self.request_url)
        result["statusCode"] = from_int(self.status_code)
        result["requestLine"] = from_str(self.request_line)
        result["requestHeaders"] = from_list(from_str, self.request_headers)
        result["responseLine"] = from_str(self.response_line)
        result["responseHeadersRaw"] = from_list(from_str, self.response_headers_raw)
        result["responseHeaders"] = from_list(lambda x: to_class(ResponseHeader, x), self.response_headers)
        result["fragileServer"] = from_bool(self.fragile_server)
        return result


@dataclass
class NamedGroupsList:
    id: int
    name: str
    bits: int
    named_group_type: str

    @staticmethod
    def from_dict(obj: Any) -> 'NamedGroupsList':
        assert isinstance(obj, dict)
        id = from_int(obj.get("id"))
        name = from_str(obj.get("name"))
        bits = from_int(obj.get("bits"))
        named_group_type = from_str(obj.get("namedGroupType"))
        return NamedGroupsList(id, name, bits, named_group_type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_int(self.id)
        result["name"] = from_str(self.name)
        result["bits"] = from_int(self.bits)
        result["namedGroupType"] = from_str(self.named_group_type)
        return result


@dataclass
class NamedGroups:
    list: List[NamedGroupsList]
    preference: bool

    @staticmethod
    def from_dict(obj: Any) -> 'NamedGroups':
        assert isinstance(obj, dict)
        list = from_list(NamedGroupsList.from_dict, obj.get("list"))
        preference = from_bool(obj.get("preference"))
        return NamedGroups(list, preference)

    def to_dict(self) -> dict:
        result: dict = {}
        result["list"] = from_list(lambda x: to_class(NamedGroupsList, x), self.list)
        result["preference"] = from_bool(self.preference)
        return result


@dataclass
class Protocol:
    id: int
    name: str
    version: str

    @staticmethod
    def from_dict(obj: Any) -> 'Protocol':
        assert isinstance(obj, dict)
        id = from_int(obj.get("id"))
        name = from_str(obj.get("name"))
        version = from_str(obj.get("version"))
        return Protocol(id, name, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_int(self.id)
        result["name"] = from_str(self.name)
        result["version"] = from_str(self.version)
        return result


@dataclass
class Client:
    id: int
    name: str
    version: str
    is_reference: bool
    platform: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Client':
        assert isinstance(obj, dict)
        id = from_int(obj.get("id"))
        name = from_str(obj.get("name"))
        version = from_str(obj.get("version"))
        is_reference = from_bool(obj.get("isReference"))
        platform = from_union([from_str, from_none], obj.get("platform"))
        return Client(id, name, version, is_reference, platform)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_int(self.id)
        result["name"] = from_str(self.name)
        result["version"] = from_str(self.version)
        result["isReference"] = from_bool(self.is_reference)
        result["platform"] = from_union([from_str, from_none], self.platform)
        return result


@dataclass
class Result:
    client: Client
    error_code: int
    attempts: int
    error_message: Optional[str] = None
    cert_chain_id: Optional[str] = None
    protocol_id: Optional[int] = None
    suite_id: Optional[int] = None
    suite_name: Optional[str] = None
    kx_type: Optional[str] = None
    kx_strength: Optional[int] = None
    named_group_bits: Optional[int] = None
    named_group_id: Optional[int] = None
    named_group_name: Optional[str] = None
    key_alg: Optional[str] = None
    key_size: Optional[int] = None
    sig_alg: Optional[str] = None
    alert_type: Optional[int] = None
    alert_code: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Result':
        assert isinstance(obj, dict)
        client = Client.from_dict(obj.get("client"))
        error_code = from_int(obj.get("errorCode"))
        attempts = from_int(obj.get("attempts"))
        error_message = from_union([from_str, from_none], obj.get("errorMessage"))
        cert_chain_id = from_union([from_str, from_none], obj.get("certChainId"))
        protocol_id = from_union([from_int, from_none], obj.get("protocolId"))
        suite_id = from_union([from_int, from_none], obj.get("suiteId"))
        suite_name = from_union([from_str, from_none], obj.get("suiteName"))
        kx_type = from_union([from_str, from_none], obj.get("kxType"))
        kx_strength = from_union([from_int, from_none], obj.get("kxStrength"))
        named_group_bits = from_union([from_int, from_none], obj.get("namedGroupBits"))
        named_group_id = from_union([from_int, from_none], obj.get("namedGroupId"))
        named_group_name = from_union([from_str, from_none], obj.get("namedGroupName"))
        key_alg = from_union([from_str, from_none], obj.get("keyAlg"))
        key_size = from_union([from_int, from_none], obj.get("keySize"))
        sig_alg = from_union([from_str, from_none], obj.get("sigAlg"))
        alert_type = from_union([from_int, from_none], obj.get("alertType"))
        alert_code = from_union([from_int, from_none], obj.get("alertCode"))
        return Result(client, error_code, attempts, error_message, cert_chain_id, protocol_id, suite_id, suite_name,
                      kx_type, kx_strength, named_group_bits, named_group_id, named_group_name, key_alg, key_size,
                      sig_alg, alert_type, alert_code)

    def to_dict(self) -> dict:
        result: dict = {}
        result["client"] = to_class(Client, self.client)
        result["errorCode"] = from_int(self.error_code)
        result["attempts"] = from_int(self.attempts)
        result["errorMessage"] = from_union([from_str, from_none], self.error_message)
        result["certChainId"] = from_union([from_str, from_none], self.cert_chain_id)
        result["protocolId"] = from_union([from_int, from_none], self.protocol_id)
        result["suiteId"] = from_union([from_int, from_none], self.suite_id)
        result["suiteName"] = from_union([from_str, from_none], self.suite_name)
        result["kxType"] = from_union([from_str, from_none], self.kx_type)
        result["kxStrength"] = from_union([from_int, from_none], self.kx_strength)
        result["namedGroupBits"] = from_union([from_int, from_none], self.named_group_bits)
        result["namedGroupId"] = from_union([from_int, from_none], self.named_group_id)
        result["namedGroupName"] = from_union([from_str, from_none], self.named_group_name)
        result["keyAlg"] = from_union([from_str, from_none], self.key_alg)
        result["keySize"] = from_union([from_int, from_none], self.key_size)
        result["sigAlg"] = from_union([from_str, from_none], self.sig_alg)
        result["alertType"] = from_union([from_int, from_none], self.alert_type)
        result["alertCode"] = from_union([from_int, from_none], self.alert_code)
        return result


@dataclass
class Sims:
    results: List[Result]

    @staticmethod
    def from_dict(obj: Any) -> 'Sims':
        assert isinstance(obj, dict)
        results = from_list(Result.from_dict, obj.get("results"))
        return Sims(results)

    def to_dict(self) -> dict:
        result: dict = {}
        result["results"] = from_list(lambda x: to_class(Result, x), self.results)
        return result


@dataclass
class StaticPkpPolicy:
    status: SPKP
    pins: List[Any]
    matched_pins: List[Any]
    forbidden_pins: List[Any]
    matched_forbidden_pins: List[Any]

    @staticmethod
    def from_dict(obj: Any) -> 'StaticPkpPolicy':
        assert isinstance(obj, dict)
        status = from_str(obj.get("status"))
        pins = from_list(lambda x: x, obj.get("pins"))
        matched_pins = from_list(lambda x: x, obj.get("matchedPins"))
        forbidden_pins = from_list(lambda x: x, obj.get("forbiddenPins"))
        matched_forbidden_pins = from_list(lambda x: x, obj.get("matchedForbiddenPins"))
        return StaticPkpPolicy(status, pins, matched_pins, forbidden_pins, matched_forbidden_pins)

    def to_dict(self) -> dict:
        result: dict = {}
        result["status"] = from_str(self.status)
        result["pins"] = from_list(lambda x: x, self.pins)
        result["matchedPins"] = from_list(lambda x: x, self.matched_pins)
        result["forbiddenPins"] = from_list(lambda x: x, self.forbidden_pins)
        result["matchedForbiddenPins"] = from_list(lambda x: x, self.matched_forbidden_pins)
        return result


@dataclass
class SuiteList:
    id: int
    name: str
    cipher_strength: int
    kx_type: str
    kx_strength: int
    named_group_bits: int
    named_group_id: int
    named_group_name: str
    q: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SuiteList':
        assert isinstance(obj, dict)
        id = from_int(obj.get("id"))
        name = from_str(obj.get("name"))
        cipher_strength = from_int(obj.get("cipherStrength"))
        kx_type = from_str(obj.get("kxType"))
        kx_strength = from_int(obj.get("kxStrength"))
        named_group_bits = from_int(obj.get("namedGroupBits"))
        named_group_id = from_int(obj.get("namedGroupId"))
        named_group_name = from_str(obj.get("namedGroupName"))
        q = from_union([from_int, from_none], obj.get("q"))
        return SuiteList(id, name, cipher_strength, kx_type, kx_strength, named_group_bits, named_group_id,
                         named_group_name, q)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_int(self.id)
        result["name"] = from_str(self.name)
        result["cipherStrength"] = from_int(self.cipher_strength)
        result["kxType"] = from_str(self.kx_type)
        result["kxStrength"] = from_int(self.kx_strength)
        result["namedGroupBits"] = from_int(self.named_group_bits)
        result["namedGroupId"] = from_int(self.named_group_id)
        result["namedGroupName"] = from_str(self.named_group_name)
        result["q"] = from_union([from_int, from_none], self.q)
        return result


@dataclass
class Suite:
    protocol: int
    list: List[SuiteList]
    preference: Optional[bool] = None
    cha_cha20_preference: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Suite':
        assert isinstance(obj, dict)
        protocol = from_int(obj.get("protocol"))
        list = from_list(SuiteList.from_dict, obj.get("list"))
        preference = from_union([from_bool, from_none], obj.get("preference"))
        cha_cha20_preference = from_union([from_bool, from_none], obj.get("chaCha20Preference"))
        return Suite(protocol, list, preference, cha_cha20_preference)

    def to_dict(self) -> dict:
        result: dict = {}
        result["protocol"] = from_int(self.protocol)
        result["list"] = from_list(lambda x: to_class(SuiteList, x), self.list)
        result["preference"] = from_union([from_bool, from_none], self.preference)
        result["chaCha20Preference"] = from_union([from_bool, from_none], self.cha_cha20_preference)
        return result


@dataclass
class Details:
    host_start_time: int
    cert_chains: List[CERTChain]
    protocols: List[Protocol]
    prefix_delegation: bool
    non_prefix_delegation: bool
    zero_rtt_enabled: int
    zombie_poodle: int
    golden_doodle: int
    zero_length_padding_oracle: int
    sleeping_poodle: int
    suites: Optional[List[Suite]] = None
    named_groups: Optional[NamedGroups] = None
    vuln_beast: Optional[bool] = None
    reneg_support: Optional[int] = None
    session_resumption: Optional[int] = None
    compression_methods: Optional[int] = None
    supports_npn: Optional[bool] = None
    npn_protocols: Optional[str] = None
    supports_alpn: Optional[bool] = None
    alpn_protocols: Optional[str] = None
    session_tickets: Optional[int] = None
    ocsp_stapling: Optional[bool] = None
    sni_required: Optional[bool] = None
    http_status_code: Optional[int] = None
    supports_rc4: Optional[bool] = None
    rc4_with_modern: Optional[bool] = None
    rc4_only: Optional[bool] = None
    forward_secrecy: Optional[int] = None
    supports_aead: Optional[bool] = None
    protocol_intolerance: Optional[int] = None
    misc_intolerance: Optional[int] = None
    sims: Optional[Sims] = None
    heartbleed: Optional[bool] = None
    heartbeat: Optional[bool] = None
    open_ssl_ccs: Optional[int] = None
    open_ssl_lucky_minus20: Optional[LUCKY_MINUS] = None
    ticketbleed: Optional[TICKETBLEED] = None
    bleichenbacher: Optional[BLEICHENBACHER] = None
    poodle: Optional[bool] = None
    poodle_tls: Optional[POODLE_TLS] = None
    fallback_scsv: Optional[bool] = None
    freak: Optional[bool] = None
    has_sct: Optional[int] = None
    ecdh_parameter_reuse: Optional[bool] = None
    logjam: Optional[bool] = None
    hsts_policy: Optional[HstsPolicy] = None
    hsts_preloads: Optional[List[HstsPreload]] = None
    hpkp_policy: Optional[HpkpPolicy] = None
    hpkp_ro_policy: Optional[HpkpPolicy] = None
    static_pkp_policy: Optional[StaticPkpPolicy] = None
    http_transactions: Optional[List[HTTPTransaction]] = None
    drown_hosts: Optional[List[Any]] = None
    drown_errors: Optional[bool] = None
    drown_vulnerable: Optional[bool] = None
    implements_tls13_mandatory_cs: Optional[bool] = None
    supports_cbc: Optional[bool] = None
    server_signature: Optional[str] = None
    stapling_revocation_status: Optional[int] = None
    cha_cha20_preference: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Details':
        assert isinstance(obj, dict)
        host_start_time = from_int(obj.get("hostStartTime"))
        cert_chains = from_list(CERTChain.from_dict, obj.get("certChains"))
        protocols = from_list(Protocol.from_dict, obj.get("protocols"))
        prefix_delegation = from_bool(obj.get("prefixDelegation"))
        non_prefix_delegation = from_bool(obj.get("nonPrefixDelegation"))
        zero_rtt_enabled = from_int(obj.get("zeroRTTEnabled"))
        zombie_poodle = from_int(obj.get("zombiePoodle"))
        golden_doodle = from_int(obj.get("goldenDoodle"))
        zero_length_padding_oracle = from_int(obj.get("zeroLengthPaddingOracle"))
        sleeping_poodle = from_int(obj.get("sleepingPoodle"))
        suites = from_union([lambda x: from_list(Suite.from_dict, x), from_none], obj.get("suites"))
        named_groups = from_union([NamedGroups.from_dict, from_none], obj.get("namedGroups"))
        vuln_beast = from_union([from_bool, from_none], obj.get("vulnBeast"))
        reneg_support = from_union([from_int, from_none], obj.get("renegSupport"))
        session_resumption = from_union([from_int, from_none], obj.get("sessionResumption"))
        compression_methods = from_union([from_int, from_none], obj.get("compressionMethods"))
        supports_npn = from_union([from_bool, from_none], obj.get("supportsNpn"))
        npn_protocols = from_union([from_str, from_none], obj.get("npnProtocols"))
        supports_alpn = from_union([from_bool, from_none], obj.get("supportsAlpn"))
        alpn_protocols = from_union([from_str, from_none], obj.get("alpnProtocols"))
        session_tickets = from_union([from_int, from_none], obj.get("sessionTickets"))
        ocsp_stapling = from_union([from_bool, from_none], obj.get("ocspStapling"))
        sni_required = from_union([from_bool, from_none], obj.get("sniRequired"))
        http_status_code = from_union([from_int, from_none], obj.get("httpStatusCode"))
        supports_rc4 = from_union([from_bool, from_none], obj.get("supportsRc4"))
        rc4_with_modern = from_union([from_bool, from_none], obj.get("rc4WithModern"))
        rc4_only = from_union([from_bool, from_none], obj.get("rc4Only"))
        forward_secrecy = from_union([from_int, from_none], obj.get("forwardSecrecy"))
        supports_aead = from_union([from_bool, from_none], obj.get("supportsAead"))
        protocol_intolerance = from_union([from_int, from_none], obj.get("protocolIntolerance"))
        misc_intolerance = from_union([from_int, from_none], obj.get("miscIntolerance"))
        sims = from_union([Sims.from_dict, from_none], obj.get("sims"))
        heartbleed = from_union([from_bool, from_none], obj.get("heartbleed"))
        heartbeat = from_union([from_bool, from_none], obj.get("heartbeat"))
        open_ssl_ccs = from_union([from_int, from_none], obj.get("openSslCcs"))
        open_ssl_lucky_minus20 = from_union([from_int, from_none], obj.get("openSSLLuckyMinus20"))
        ticketbleed = from_union([from_int, from_none], obj.get("ticketbleed"))
        bleichenbacher = from_union([from_int, from_none], obj.get("bleichenbacher"))
        poodle = from_union([from_bool, from_none], obj.get("poodle"))
        poodle_tls = from_union([from_int, from_none], obj.get("poodleTls"))
        fallback_scsv = from_union([from_bool, from_none], obj.get("fallbackScsv"))
        freak = from_union([from_bool, from_none], obj.get("freak"))
        has_sct = from_union([from_int, from_none], obj.get("hasSct"))
        ecdh_parameter_reuse = from_union([from_bool, from_none], obj.get("ecdhParameterReuse"))
        logjam = from_union([from_bool, from_none], obj.get("logjam"))
        hsts_policy = from_union([HstsPolicy.from_dict, from_none], obj.get("hstsPolicy"))
        hsts_preloads = from_union([lambda x: from_list(HstsPreload.from_dict, x), from_none], obj.get("hstsPreloads"))
        hpkp_policy = from_union([HpkpPolicy.from_dict, from_none], obj.get("hpkpPolicy"))
        hpkp_ro_policy = from_union([HpkpPolicy.from_dict, from_none], obj.get("hpkpRoPolicy"))
        static_pkp_policy = from_union([StaticPkpPolicy.from_dict, from_none], obj.get("staticPkpPolicy"))
        http_transactions = from_union([lambda x: from_list(HTTPTransaction.from_dict, x), from_none],
                                       obj.get("httpTransactions"))
        drown_hosts = from_union([lambda x: from_list(lambda x: x, x), from_none], obj.get("drownHosts"))
        drown_errors = from_union([from_bool, from_none], obj.get("drownErrors"))
        drown_vulnerable = from_union([from_bool, from_none], obj.get("drownVulnerable"))
        implements_tls13_mandatory_cs = from_union([from_bool, from_none], obj.get("implementsTLS13MandatoryCS"))
        supports_cbc = from_union([from_bool, from_none], obj.get("supportsCBC"))
        server_signature = from_union([from_str, from_none], obj.get("serverSignature"))
        stapling_revocation_status = from_union([from_int, from_none], obj.get("staplingRevocationStatus"))
        cha_cha20_preference = from_union([from_bool, from_none], obj.get("chaCha20Preference"))
        return Details(host_start_time, cert_chains, protocols, prefix_delegation, non_prefix_delegation,
                       zero_rtt_enabled, zombie_poodle, golden_doodle, zero_length_padding_oracle, sleeping_poodle,
                       suites, named_groups, vuln_beast, reneg_support, session_resumption, compression_methods,
                       supports_npn, npn_protocols, supports_alpn, alpn_protocols, session_tickets, ocsp_stapling,
                       sni_required, http_status_code, supports_rc4, rc4_with_modern, rc4_only, forward_secrecy,
                       supports_aead, protocol_intolerance, misc_intolerance, sims, heartbleed, heartbeat, open_ssl_ccs,
                       open_ssl_lucky_minus20, ticketbleed, bleichenbacher, poodle, poodle_tls, fallback_scsv, freak,
                       has_sct, ecdh_parameter_reuse, logjam, hsts_policy, hsts_preloads, hpkp_policy, hpkp_ro_policy,
                       static_pkp_policy, http_transactions, drown_hosts, drown_errors, drown_vulnerable,
                       implements_tls13_mandatory_cs, supports_cbc, server_signature, stapling_revocation_status,
                       cha_cha20_preference)

    def to_dict(self) -> dict:
        result: dict = {}
        result["hostStartTime"] = from_int(self.host_start_time)
        result["certChains"] = from_list(lambda x: to_class(CERTChain, x), self.cert_chains)
        result["protocols"] = from_list(lambda x: to_class(Protocol, x), self.protocols)
        result["prefixDelegation"] = from_bool(self.prefix_delegation)
        result["nonPrefixDelegation"] = from_bool(self.non_prefix_delegation)
        result["zeroRTTEnabled"] = from_int(self.zero_rtt_enabled)
        result["zombiePoodle"] = from_int(self.zombie_poodle)
        result["goldenDoodle"] = from_int(self.golden_doodle)
        result["zeroLengthPaddingOracle"] = from_int(self.zero_length_padding_oracle)
        result["sleepingPoodle"] = from_int(self.sleeping_poodle)
        result["suites"] = from_union([lambda x: from_list(lambda x: to_class(Suite, x), x), from_none], self.suites)
        result["namedGroups"] = from_union([lambda x: to_class(NamedGroups, x), from_none], self.named_groups)
        result["vulnBeast"] = from_union([from_bool, from_none], self.vuln_beast)
        result["renegSupport"] = from_union([from_int, from_none], self.reneg_support)
        result["sessionResumption"] = from_union([from_int, from_none], self.session_resumption)
        result["compressionMethods"] = from_union([from_int, from_none], self.compression_methods)
        result["supportsNpn"] = from_union([from_bool, from_none], self.supports_npn)
        result["npnProtocols"] = from_union([from_str, from_none], self.npn_protocols)
        result["supportsAlpn"] = from_union([from_bool, from_none], self.supports_alpn)
        result["alpnProtocols"] = from_union([from_str, from_none], self.alpn_protocols)
        result["sessionTickets"] = from_union([from_int, from_none], self.session_tickets)
        result["ocspStapling"] = from_union([from_bool, from_none], self.ocsp_stapling)
        result["sniRequired"] = from_union([from_bool, from_none], self.sni_required)
        result["httpStatusCode"] = from_union([from_int, from_none], self.http_status_code)
        result["supportsRc4"] = from_union([from_bool, from_none], self.supports_rc4)
        result["rc4WithModern"] = from_union([from_bool, from_none], self.rc4_with_modern)
        result["rc4Only"] = from_union([from_bool, from_none], self.rc4_only)
        result["forwardSecrecy"] = from_union([from_int, from_none], self.forward_secrecy)
        result["supportsAead"] = from_union([from_bool, from_none], self.supports_aead)
        result["protocolIntolerance"] = from_union([from_int, from_none], self.protocol_intolerance)
        result["miscIntolerance"] = from_union([from_int, from_none], self.misc_intolerance)
        result["sims"] = from_union([lambda x: to_class(Sims, x), from_none], self.sims)
        result["heartbleed"] = from_union([from_bool, from_none], self.heartbleed)
        result["heartbeat"] = from_union([from_bool, from_none], self.heartbeat)
        result["openSslCcs"] = from_union([from_int, from_none], self.open_ssl_ccs)
        result["openSSLLuckyMinus20"] = from_union([from_int, from_none], self.open_ssl_lucky_minus20)
        result["ticketbleed"] = from_union([from_int, from_none], self.ticketbleed)
        result["bleichenbacher"] = from_union([from_int, from_none], self.bleichenbacher)
        result["poodle"] = from_union([from_bool, from_none], self.poodle)
        result["poodleTls"] = from_union([from_int, from_none], self.poodle_tls)
        result["fallbackScsv"] = from_union([from_bool, from_none], self.fallback_scsv)
        result["freak"] = from_union([from_bool, from_none], self.freak)
        result["hasSct"] = from_union([from_int, from_none], self.has_sct)
        result["ecdhParameterReuse"] = from_union([from_bool, from_none], self.ecdh_parameter_reuse)
        result["logjam"] = from_union([from_bool, from_none], self.logjam)
        result["hstsPolicy"] = from_union([lambda x: to_class(HstsPolicy, x), from_none], self.hsts_policy)
        result["hstsPreloads"] = from_union([lambda x: from_list(lambda x: to_class(HstsPreload, x), x), from_none],
                                            self.hsts_preloads)
        result["hpkpPolicy"] = from_union([lambda x: to_class(HpkpPolicy, x), from_none], self.hpkp_policy)
        result["hpkpRoPolicy"] = from_union([lambda x: to_class(HpkpPolicy, x), from_none], self.hpkp_ro_policy)
        result["staticPkpPolicy"] = from_union([lambda x: to_class(StaticPkpPolicy, x), from_none],
                                               self.static_pkp_policy)
        result["httpTransactions"] = from_union(
            [lambda x: from_list(lambda x: to_class(HTTPTransaction, x), x), from_none], self.http_transactions)
        result["drownHosts"] = from_union([lambda x: from_list(lambda x: x, x), from_none], self.drown_hosts)
        result["drownErrors"] = from_union([from_bool, from_none], self.drown_errors)
        result["drownVulnerable"] = from_union([from_bool, from_none], self.drown_vulnerable)
        result["implementsTLS13MandatoryCS"] = from_union([from_bool, from_none], self.implements_tls13_mandatory_cs)
        result["supportsCBC"] = from_union([from_bool, from_none], self.supports_cbc)
        result["serverSignature"] = from_union([from_str, from_none], self.server_signature)
        result["staplingRevocationStatus"] = from_union([from_int, from_none], self.stapling_revocation_status)
        result["chaCha20Preference"] = from_union([from_bool, from_none], self.cha_cha20_preference)
        return result


@dataclass
class Endpoint:
    ip_address: str
    status_message: str
    duration: int
    delegation: int
    details: Details
    server_name: Optional[str] = None
    status_details: Optional[str] = None
    status_details_message: Optional[str] = None
    grade: Optional[str] = None
    grade_trust_ignored: Optional[str] = None
    has_warnings: Optional[bool] = None
    is_exceptional: Optional[bool] = None
    progress: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Endpoint':
        assert isinstance(obj, dict)
        ip_address = from_str(obj.get("ipAddress"))
        status_message = from_str(obj.get("statusMessage"))
        duration = from_int(obj.get("duration"))
        delegation = from_int(obj.get("delegation"))
        details = Details.from_dict(obj.get("details"))
        server_name = from_union([from_str, from_none], obj.get("serverName"))
        status_details = from_union([from_str, from_none], obj.get("statusDetails"))
        status_details_message = from_union([from_str, from_none], obj.get("statusDetailsMessage"))
        grade = from_union([from_str, from_none], obj.get("grade"))
        grade_trust_ignored = from_union([from_str, from_none], obj.get("gradeTrustIgnored"))
        has_warnings = from_union([from_bool, from_none], obj.get("hasWarnings"))
        is_exceptional = from_union([from_bool, from_none], obj.get("isExceptional"))
        progress = from_union([from_int, from_none], obj.get("progress"))
        return Endpoint(ip_address, status_message, duration, delegation, details, server_name, status_details,
                        status_details_message, grade, grade_trust_ignored, has_warnings, is_exceptional, progress)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ipAddress"] = from_str(self.ip_address)
        result["statusMessage"] = from_str(self.status_message)
        result["duration"] = from_int(self.duration)
        result["delegation"] = from_int(self.delegation)
        result["details"] = to_class(Details, self.details)
        result["serverName"] = from_union([from_str, from_none], self.server_name)
        result["statusDetails"] = from_union([from_str, from_none], self.status_details)
        result["statusDetailsMessage"] = from_union([from_str, from_none], self.status_details_message)
        result["grade"] = from_union([from_str, from_none], self.grade)
        result["gradeTrustIgnored"] = from_union([from_str, from_none], self.grade_trust_ignored)
        result["hasWarnings"] = from_union([from_bool, from_none], self.has_warnings)
        result["isExceptional"] = from_union([from_bool, from_none], self.is_exceptional)
        result["progress"] = from_union([from_int, from_none], self.progress)
        return result


@dataclass
class TopLevelElement:
    host: str
    port: int
    protocol: str
    is_public: bool
    status: str
    start_time: int
    test_time: int
    engine_version: str
    criteria_version: str
    status_message: Optional[str] = None
    cache_expiry_time: Optional[int] = None
    endpoints: Optional[List[Endpoint]] = None
    certs: Optional[List[CERT]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'TopLevelElement':
        assert isinstance(obj, dict)
        host = from_str(obj.get("host"))
        port = from_int(obj.get("port"))
        protocol = from_str(obj.get("protocol"))
        is_public = from_bool(obj.get("isPublic"))
        status = from_str(obj.get("status"))
        start_time = from_int(obj.get("startTime"))
        test_time = from_int(obj.get("testTime"))
        engine_version = from_str(obj.get("engineVersion"))
        criteria_version = from_str(obj.get("criteriaVersion"))
        status_message = from_union([from_str, from_none], obj.get("statusMessage"))
        cache_expiry_time = from_union([from_int, from_none], obj.get("cacheExpiryTime"))
        endpoints = from_union([lambda x: from_list(Endpoint.from_dict, x), from_none], obj.get("endpoints"))
        certs = from_union([lambda x: from_list(CERT.from_dict, x), from_none], obj.get("certs"))
        return TopLevelElement(host, port, protocol, is_public, status, start_time, test_time, engine_version,
                               criteria_version, status_message, cache_expiry_time, endpoints, certs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["host"] = from_str(self.host)
        result["port"] = from_int(self.port)
        result["protocol"] = from_str(self.protocol)
        result["isPublic"] = from_bool(self.is_public)
        result["status"] = from_str(self.status)
        result["startTime"] = from_int(self.start_time)
        result["testTime"] = from_int(self.test_time)
        result["engineVersion"] = from_str(self.engine_version)
        result["criteriaVersion"] = from_str(self.criteria_version)
        result["statusMessage"] = from_union([from_str, from_none], self.status_message)
        result["cacheExpiryTime"] = from_union([from_int, from_none], self.cache_expiry_time)
        result["endpoints"] = from_union([lambda x: from_list(lambda x: to_class(Endpoint, x), x), from_none],
                                         self.endpoints)
        result["certs"] = from_union([lambda x: from_list(lambda x: to_class(CERT, x), x), from_none], self.certs)
        return result


def top_level_from_dict(s: Any) -> List[TopLevelElement]:
    return from_list(TopLevelElement.from_dict, s)


def top_level_to_dict(x: List[TopLevelElement]) -> Any:
    return from_list(lambda x: to_class(TopLevelElement, x), x)
