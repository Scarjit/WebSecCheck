import json
import json
import subprocess
import sys

from Bulletin import Bulletin, IssueLevel
from scanners.ssllabs import results
from scanners.ssllabs.results import top_level_from_dict, LUCKY_MINUS, ProtocolVersion, SPKP, HPKP, HSTS, POODLE_TLS, \
    BLEICHENBACHER, TICKETBLEED


class SSLLabs:
    result: results = None

    def __init__(self, url: str):
        print("Initializing ssllabs")
        raw_res = None
        if sys.platform.startswith("win32"):
            raw_res = subprocess.run(
                ["./ssllabs-scan/ssllabs-scan-v3.exe",
                 "--usecache",
                 "false",
                 url],
                stdout=subprocess.PIPE
            )
        else:
            raw_res = subprocess.run(
                ["./ssllabs-scan/ssllabs-scan-v3",
                 "--usecache",
                 "false",
                 url],
                stdout=subprocess.PIPE
            )
        decoded_res = raw_res.stdout.decode('utf-8')
        self.result = top_level_from_dict(json.loads(decoded_res))

    def GetBulletin(self) -> list[Bulletin]:
        bull = list()
        for result in self.result:
            if result.status != "READY":
                bull.append(Bulletin("Test failed", result.status_message, result, IssueLevel.WARN))
                continue

            for ep in result.endpoints:
                if ep.status_message != "Ready":
                    bull.append(Bulletin("Endpoint failed", ep.status_message, ep, IssueLevel.WARN))
                    continue

                # print(json.dumps(ep.to_dict(), indent=4, sort_keys=True))

                if ep.details.sleeping_poodle == 0:
                    bull.append(
                        Bulletin("sleeping_poodle", "Sleeping Poodle vulnerability", None, IssueLevel.ERR)
                    )

                dt = ep.details

                if dt.zero_rtt_enabled:
                    bull.append(
                        Bulletin("zero_rtt_enable", "Zero RTT for TLS 1.3 not enabled", None, IssueLevel.INFO)
                    )

                if not dt.implements_tls13_mandatory_cs:
                    bull.append(
                        Bulletin("implements_tls13_mandatory_cs", "Server supports TLS 1.3 but does not support "
                                                                  "mandatory Cipher Suites", None, IssueLevel.WARN)
                    )

                if dt.drown_vulnerable:
                    bull.append(
                        Bulletin("drown_vulnerable", "Drown vulnerability", dt.drown_hosts, IssueLevel.ERR)
                    )

                if dt.static_pkp_policy.status != SPKP.SPKP_STATUS_VALID:
                    bull.append(
                        Bulletin("static_pkp_policy", "SPKP policy issue", dt.static_pkp_policy, IssueLevel.INFO)
                    )
                if dt.hpkp_policy.status != HPKP.HPKP_STATUS_VALID:
                    bull.append(
                        Bulletin("hpkp_policy", "No HPKP policy present", dt.hpkp_policy, IssueLevel.INFO)
                    )
                if dt.hpkp_ro_policy.status != HPKP.HPKP_STATUS_VALID:
                    bull.append(
                        Bulletin("hpkp_ro_policy", "No HPKP RO policy present", dt.hpkp_ro_policy, IssueLevel.INFO)
                    )

                for preloads in dt.hsts_preloads:
                    if preloads.status != HSTS.HSTS_STATUS_PRESENT:
                        bull.append(Bulletin("hsts_preload_absent", f"No HSTS preloading in {preloads.source}", None,
                                             IssueLevel.INFO))

                if dt.hsts_policy.status != HSTS.HSTS_STATUS_PRESENT:
                    bull.append(
                        Bulletin("hsts_policy", "No HSTS policy present", None, IssueLevel.WARN)
                    )

                if dt.logjam:
                    bull.append(
                        Bulletin("logjam", "Logjam vulnerability", None, IssueLevel.ERR)
                    )

                if dt.ecdh_parameter_reuse:
                    bull.append(
                        Bulletin("ecdh_parameter_reuse", "ecdh_parameter_reuse vulnerability", None, IssueLevel.ERR)
                    )

                if dt.has_sct == 0:
                    bull.append(
                        Bulletin("hasSct", "Certificate contains no SCT", None, IssueLevel.INFO)
                    )

                if dt.freak:
                    bull.append(
                        Bulletin("freak", "freak vulnerability", None, IssueLevel.ERR)
                    )

                if not dt.fallback_scsv:
                    bull.append(
                        Bulletin("fallback_scsv",
                                 "TLS Fallback cipher suite values not supported. This is only an issue with older TLS/SSL versions",
                                 None, IssueLevel.INFO)
                    )
                if dt.poodle_tls != POODLE_TLS.POODLE_STATUS_NOT_VULNERABLE.value:
                    bull.append(
                        Bulletin("poodle_tls", "poodle_tls vulnerability", dt.poodle_tls, IssueLevel.ERR)
                    )
                if dt.poodle:
                    bull.append(
                        Bulletin("poodle", "poodle vulnerability", None, IssueLevel.ERR)
                    )
                if dt.bleichenbacher != BLEICHENBACHER.BLEICHENBACHER_STATUS_NOT_VULNERABLE.value:
                    bull.append(
                        Bulletin("bleichenbacher", "bleichenbacher vulnerability", dt.bleichenbacher, IssueLevel.ERR)
                    )
                if dt.ticketbleed != TICKETBLEED.TICKETBLEED_STATUS_NOT_VULNERABLE.value:
                    bull.append(
                        Bulletin("ticketbleed", "ticketbleed vulnerability", dt.ticketbleed, IssueLevel.ERR)
                    )
                if dt.open_ssl_lucky_minus20 != LUCKY_MINUS.LUCKY_MINUS_STATUS_NOT_VULNERABLE.value:
                    bull.append(
                        Bulletin("open_ssl_lucky_minus20", "open_ssl_lucky_minus20 vulnerability",
                                 dt.open_ssl_lucky_minus20, IssueLevel.ERR)
                    )
                if dt.open_ssl_ccs == 0:
                    bull.append(
                        Bulletin("open_ssl_ccs", "open_ssl_ccs vulnerability", None, IssueLevel.ERR)
                    )
                if dt.heartbeat:
                    bull.append(
                        Bulletin("heartbeat", "heartbeat vulnerability", None, IssueLevel.ERR)
                    )
                if dt.heartbleed:
                    bull.append(
                        Bulletin("heartbleed", "heartbleed vulnerability", None, IssueLevel.ERR)
                    )
                if dt.misc_intolerance != 0:
                    bull.append(
                        Bulletin("misc_intolerance", "protocol version intolerance issues", None, IssueLevel.INFO)
                    )
                if dt.protocol_intolerance != 0:
                    bull.append(
                        Bulletin("protocol_intolerance", "protocol version intolerance issues", None, IssueLevel.INFO)
                    )
                if not dt.supports_aead:
                    bull.append(
                        Bulletin("supports_aead", "server does not support aead ciphers", None, IssueLevel.INFO)
                    )

                if dt.forward_secrecy < 4:
                    bull.append(
                        Bulletin("forward_secrecy", "No strong forward secrecy deployed", None, IssueLevel.WARN)
                    )

                if dt.supports_rc4:
                    bull.append(
                        Bulletin("supports_rc4", "RC4 is considered to be an weak cipher", None, IssueLevel.ERR)
                    )

                if not dt.ocsp_stapling:
                    bull.append(
                        Bulletin("ocsp_stapling", "No OCSP Stapling support", None, IssueLevel.WARN)
                    )
                if dt.session_tickets == 0:
                    bull.append(
                        Bulletin("session_tickets", "No sesson ticket support", None, IssueLevel.INFO)
                    )

                if not dt.supports_alpn:
                    bull.append(
                        Bulletin("supports_alpn", "No ALPN support", None, IssueLevel.INFO)
                    )

                if not dt.supports_npn:
                    bull.append(
                        Bulletin("supports_npn", "No NPN support", None, IssueLevel.INFO)
                    )

                if dt.compression_methods != 0:
                    bull.append(
                        Bulletin("compression_methods", "TLS compression can compromise security", None,
                                 IssueLevel.WARN)
                    )

                if dt.session_resumption != 2:
                    bull.append(
                        Bulletin("session_resumption", "Session resumption not supported", None, IssueLevel.INFO)
                    )

                if dt.reneg_support != 2:
                    bull.append(
                        Bulletin("reneg_support", "Secure renegotiation not supported", None, IssueLevel.WARN)
                    )

                if dt.vuln_beast:
                    # TLS 1.0 and lower
                    if any(elem.id <= ProtocolVersion.PROTOCOL_TLS10.value for elem in dt.protocols):
                        bull.append(
                            Bulletin("vuln_beast", "BEAST vulnerability.", None, IssueLevel.WARN)
                        )

                if dt.sleeping_poodle != 1:
                    bull.append(
                        Bulletin("sleeping_poodle", "sleeping_poodle vulnerability", None, IssueLevel.ERR)
                    )

                if dt.zero_length_padding_oracle != 1:
                    bull.append(
                        Bulletin("zero_length_padding_oracle", "zero_length_padding_oracle vulnerability", None,
                                 IssueLevel.ERR)
                    )
                if dt.golden_doodle != 1:
                    bull.append(
                        Bulletin("golden_doodle", "golden_doodle vulnerability", None, IssueLevel.ERR)
                    )
                if dt.zombie_poodle != 1:
                    bull.append(
                        Bulletin("zombie_poodle", "zombie_poodle vulnerability", None, IssueLevel.ERR)
                    )

        return bull
