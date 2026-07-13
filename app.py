from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import httpx
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware


APP_VERSION = "2.0.0"
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 750_000
ALLOWED_PORTS = {80, 443}

REQUEST_TIMEOUT = httpx.Timeout(
    connect=6.0,
    read=10.0,
    write=5.0,
    pool=5.0,
)

SECURITY_HEADERS = {
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "severity": "high",
        "code": "HEADER_CSP_MISSING",
        "recommendation": (
            "Configure a restrictive Content-Security-Policy and avoid "
            "unsafe-inline and unsafe-eval whenever possible."
        ),
    },
    "strict-transport-security": {
        "label": "Strict-Transport-Security",
        "severity": "high",
        "code": "HEADER_HSTS_MISSING",
        "recommendation": (
            "Enable HSTS with an appropriate max-age and consider "
            "includeSubDomains after validating all subdomains."
        ),
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity": "medium",
        "code": "HEADER_X_FRAME_OPTIONS_MISSING",
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or enforce "
            "frame-ancestors through CSP."
        ),
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "medium",
        "code": "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity": "low",
        "code": "HEADER_REFERRER_POLICY_MISSING",
        "recommendation": (
            "Configure a restrictive Referrer-Policy such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity": "low",
        "code": "HEADER_PERMISSIONS_POLICY_MISSING",
        "recommendation": (
            "Restrict browser capabilities that the application does not use."
        ),
    },
    "cross-origin-opener-policy": {
        "label": "Cross-Origin-Opener-Policy",
        "severity": "low",
        "code": "HEADER_COOP_MISSING",
        "recommendation": (
            "Consider Cross-Origin-Opener-Policy: same-origin when compatible."
        ),
    },
    "cross-origin-resource-policy": {
        "label": "Cross-Origin-Resource-Policy",
        "severity": "low",
        "code": "HEADER_CORP_MISSING",
        "recommendation": (
            "Define an appropriate Cross-Origin-Resource-Policy."
        ),
    },
    "cross-origin-embedder-policy": {
        "label": "Cross-Origin-Embedder-Policy",
        "severity": "info",
        "code": "HEADER_COEP_MISSING",
        "recommendation": (
            "Evaluate Cross-Origin-Embedder-Policy when cross-origin "
            "isolation is required."
        ),
    },
    "cache-control": {
        "label": "Cache-Control",
        "severity": "info",
        "code": "HEADER_CACHE_CONTROL_MISSING",
        "recommendation": (
            "Define explicit caching behavior, especially for sensitive pages."
        ),
    },
    "clear-site-data": {
        "label": "Clear-Site-Data",
        "severity": "info",
        "code": "HEADER_CLEAR_SITE_DATA_MISSING",
        "recommendation": (
            "Consider Clear-Site-Data for logout or account-reset workflows."
        ),
    },
}

SEVERITY_DEDUCTION = {
    "critical": 25,
    "high": 14,
    "medium": 7,
    "low": 3,
    "info": 0,
}


app = FastAPI(
    title="WebSurface QuickScan API",
    description=(
        "Passive website security surface analysis covering TLS certificates, "
        "security headers, cookies, redirects, CORS and HTML configuration."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_finding(
    findings: list[dict[str, Any]],
    severity: str,
    code: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: Any | None = None,
) -> None:
    finding: dict[str, Any] = {
        "severity": severity,
        "code": code,
        "title": title,
        "description": description,
        "recommendation": recommendation,
    }

    if evidence is not None:
        finding["evidence"] = evidence

    findings.append(finding)


def flatten_x509_name(name: x509.Name) -> str:
    values = []

    for attribute in name:
        readable_name = attribute.oid._name or attribute.oid.dotted_string
        values.append(f"{readable_name}={attribute.value}")

    return ", ".join(values)


def calculate_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def validate_rapidapi_proxy_secret(
    received_secret: str | None,
) -> None:
    configured_secret = os.getenv("RAPIDAPI_PROXY_SECRET", "").strip()

    if not configured_secret:
        return

    if not received_secret:
        raise HTTPException(
            status_code=403,
            detail="This endpoint must be called through the authorized gateway.",
        )

    if not hashlib.compare_digest(configured_secret, received_secret):
        raise HTTPException(
            status_code=403,
            detail="Invalid API gateway credentials.",
        )


def resolve_public_ips(hostname: str, port: int) -> list[str]:
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve hostname: {exc}") from exc

    resolved_ips = sorted({result[4][0] for result in results})

    if not resolved_ips:
        raise ValueError("The hostname did not resolve to an IP address.")

    for raw_ip in resolved_ips:
        ip = ipaddress.ip_address(raw_ip)

        if not ip.is_global:
            raise ValueError(
                "Private, local, reserved or non-public IP addresses are blocked."
            )

    return resolved_ips


def validate_target_url(raw_url: str) -> dict[str, Any]:
    if len(raw_url) > 2048:
        raise ValueError("The URL exceeds the maximum permitted length.")

    parsed = urlparse(raw_url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL must include a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not allowed.")

    hostname = parsed.hostname.rstrip(".").lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
    }

    if (
        hostname in blocked_names
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".localhost")
    ):
        raise ValueError("Local and internal hostnames are blocked.")

    try:
        direct_ip = ipaddress.ip_address(hostname)
    except ValueError:
        direct_ip = None

    if direct_ip is not None and not direct_ip.is_global:
        raise ValueError(
            "Private, local, reserved or non-public IP addresses are blocked."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    if port not in ALLOWED_PORTS:
        raise ValueError("Only ports 80 and 443 are permitted.")

    resolved_ips = resolve_public_ips(hostname, port)

    return {
        "hostname": hostname,
        "port": port,
        "scheme": parsed.scheme,
        "resolved_ips": resolved_ips,
    }


def inspect_tls_certificate(hostname: str, port: int) -> dict[str, Any]:
    verified = True
    verification_error: str | None = None
    certificate_der: bytes | None = None
    tls_version: str | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None

    try:
        verified_context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=6,
        ) as tcp_socket:
            with verified_context.wrap_socket(
                tcp_socket,
                server_hostname=hostname,
            ) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                tls_version = tls_socket.version()

                cipher = tls_socket.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    cipher_bits = cipher[2]

    except Exception as exc:
        verified = False
        verification_error = str(exc)

        try:
            unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port),
                timeout=6,
            ) as tcp_socket:
                with unverified_context.wrap_socket(
                    tcp_socket,
                    server_hostname=hostname,
                ) as tls_socket:
                    certificate_der = tls_socket.getpeercert(binary_form=True)
                    tls_version = tls_socket.version()

                    cipher = tls_socket.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_bits = cipher[2]

        except Exception as fallback_exc:
            return {
                "available": False,
                "trusted": False,
                "verification_error": verification_error,
                "connection_error": str(fallback_exc),
            }

    if not certificate_der:
        return {
            "available": False,
            "trusted": verified,
            "verification_error": verification_error,
        }

    certificate = x509.load_der_x509_certificate(
        certificate_der,
        default_backend(),
    )

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    now = datetime.now(timezone.utc)
    days_remaining = int((not_after - now).total_seconds() // 86400)

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san_names = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []

    return {
        "available": True,
        "trusted": verified,
        "verification_error": verification_error,
        "subject": flatten_x509_name(certificate.subject),
        "issuer": flatten_x509_name(certificate.issuer),
        "serial_number": format(certificate.serial_number, "X"),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "currently_valid": not_before <= now <= not_after,
        "days_remaining": days_remaining,
        "signature_algorithm": (
            certificate.signature_hash_algorithm.name
            if certificate.signature_hash_algorithm
            else None
        ),
        "san_count": len(san_names),
        "subject_alt_names": san_names[:100],
        "tls_version": tls_version,
        "cipher": cipher_name,
        "cipher_bits": cipher_bits,
    }


async def get_tls_information(
    hostname: str,
    port: int,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        inspect_tls_certificate,
        hostname,
        port,
    )


async def fetch_target(
    initial_url: str,
) -> dict[str, Any]:
    current_url = initial_url
    redirect_chain: list[dict[str, Any]] = []
    final_result: dict[str, Any] | None = None

    headers = {
        "User-Agent": (
            "WebSurface-QuickScan/2.0 "
            "(Passive security configuration analyzer)"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/json,"
            "text/plain;q=0.9,*/*;q=0.5"
        ),
    }

    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        headers=headers,
        http2=True,
        verify=True,
    ) as client:
        for redirect_number in range(MAX_REDIRECTS + 1):
            validation = await asyncio.to_thread(
                validate_target_url,
                current_url,
            )

            started = time.perf_counter()

            try:
                async with client.stream("GET", current_url) as response:
                    elapsed_ms = round(
                        (time.perf_counter() - started) * 1000,
                        2,
                    )

                    response_headers = {
                        key.lower(): value
                        for key, value in response.headers.items()
                    }

                    body = bytearray()
                    body_truncated = False

                    async for chunk in response.aiter_bytes():
                        remaining = MAX_BODY_BYTES - len(body)

                        if remaining <= 0:
                            body_truncated = True
                            break

                        body.extend(chunk[:remaining])

                        if len(chunk) > remaining:
                            body_truncated = True
                            break

                    status_code = response.status_code
                    location = response.headers.get("location")

                    hop = {
                        "url": current_url,
                        "status_code": status_code,
                        "response_time_ms": elapsed_ms,
                        "resolved_ips": validation["resolved_ips"],
                    }

                    if (
                        status_code in {301, 302, 303, 307, 308}
                        and location
                    ):
                        next_url = urljoin(current_url, location)
                        hop["location"] = next_url
                        redirect_chain.append(hop)

                        if redirect_number >= MAX_REDIRECTS:
                            raise HTTPException(
                                status_code=422,
                                detail=(
                                    f"Maximum of {MAX_REDIRECTS} redirects exceeded."
                                ),
                            )

                        await asyncio.to_thread(
                            validate_target_url,
                            next_url,
                        )

                        current_url = next_url
                        continue

                    redirect_chain.append(hop)

                    final_result = {
                        "final_url": str(response.url),
                        "status_code": status_code,
                        "http_version": response.http_version,
                        "response_time_ms": elapsed_ms,
                        "headers": response_headers,
                        "set_cookie_headers": response.headers.get_list(
                            "set-cookie"
                        ),
                        "content": bytes(body),
                        "content_type": response_headers.get(
                            "content-type",
                            "",
                        ),
                        "content_encoding": response_headers.get(
                            "content-encoding"
                        ),
                        "body_bytes_analyzed": len(body),
                        "body_truncated": body_truncated,
                        "redirect_chain": redirect_chain,
                        "resolved_ips": validation["resolved_ips"],
                    }
                    break

            except httpx.TimeoutException as exc:
                raise HTTPException(
                    status_code=504,
                    detail=f"The target website timed out: {exc}",
                ) from exc

            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"Unable to connect to the target website: {exc}",
                ) from exc

    if final_result is None:
        raise HTTPException(
            status_code=502,
            detail="The website did not return a final response.",
        )

    return final_result


def analyze_headers(
    headers: dict[str, str],
    final_scheme: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    results: dict[str, Any] = {}

    csp_value = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()

    for header_name, rule in SECURITY_HEADERS.items():
        present = header_name in headers
        value = headers.get(header_name)

        results[header_name] = {
            "present": present,
            "value": value,
        }

        if present:
            continue

        if (
            header_name == "strict-transport-security"
            and final_scheme != "https"
        ):
            continue

        if (
            header_name == "x-frame-options"
            and has_frame_ancestors
        ):
            results[header_name]["covered_by_csp_frame_ancestors"] = True
            continue

        add_finding(
            findings=findings,
            severity=rule["severity"],
            code=rule["code"],
            title=f"Missing {rule['label']} header",
            description=(
                f"The response does not include the "
                f"{rule['label']} security header."
            ),
            recommendation=rule["recommendation"],
        )

    if csp_value:
        lowered_csp = csp_value.lower()

        if "'unsafe-inline'" in lowered_csp:
            add_finding(
                findings,
                "medium",
                "CSP_UNSAFE_INLINE",
                "CSP permits unsafe-inline",
                "The CSP includes unsafe-inline, which weakens script or style protection.",
                "Prefer nonces, hashes or external trusted resources.",
                "'unsafe-inline'",
            )

        if "'unsafe-eval'" in lowered_csp:
            add_finding(
                findings,
                "high",
                "CSP_UNSAFE_EVAL",
                "CSP permits unsafe-eval",
                "The CSP allows eval-like JavaScript execution.",
                "Remove unsafe-eval and refactor incompatible JavaScript.",
                "'unsafe-eval'",
            )

    hsts_value = headers.get("strict-transport-security", "")

    if hsts_value and "max-age=0" in hsts_value.lower():
        add_finding(
            findings,
            "high",
            "HSTS_DISABLED",
            "HSTS is explicitly disabled",
            "Strict-Transport-Security contains max-age=0.",
            "Set a positive max-age after confirming HTTPS readiness.",
            hsts_value,
        )

    x_content_type = headers.get("x-content-type-options", "")

    if x_content_type and x_content_type.lower().strip() != "nosniff":
        add_finding(
            findings,
            "medium",
            "X_CONTENT_TYPE_INVALID",
            "Unexpected X-Content-Type-Options value",
            "The header is present but is not set to nosniff.",
            "Set X-Content-Type-Options: nosniff.",
            x_content_type,
        )

    cors_origin = headers.get("access-control-allow-origin")

    cors_analysis = {
        "allow_origin": cors_origin,
        "allow_credentials": headers.get(
            "access-control-allow-credentials"
        ),
        "allow_methods": headers.get("access-control-allow-methods"),
        "allow_headers": headers.get("access-control-allow-headers"),
        "wildcard_origin": cors_origin == "*",
    }

    if (
        cors_origin == "*"
        and headers.get(
            "access-control-allow-credentials",
            "",
        ).lower() == "true"
    ):
        add_finding(
            findings,
            "high",
            "CORS_WILDCARD_WITH_CREDENTIALS",
            "Risky CORS configuration",
            "The response advertises wildcard origins together with credentials.",
            "Allow only explicitly trusted origins and review credential usage.",
        )
    elif cors_origin == "*":
        add_finding(
            findings,
            "low",
            "CORS_WILDCARD",
            "Wildcard CORS origin",
            "Any origin may read this resource when browser rules permit it.",
            "Confirm that the resource is intentionally public.",
            cors_origin,
        )

    disclosure = {
        "server": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "via": headers.get("via"),
    }

    if disclosure["server"]:
        add_finding(
            findings,
            "low",
            "SERVER_HEADER_DISCLOSURE",
            "Server technology is disclosed",
            "The Server response header exposes infrastructure information.",
            "Remove or generalize the Server header where operationally possible.",
            disclosure["server"],
        )

    if disclosure["x_powered_by"]:
        add_finding(
            findings,
            "low",
            "X_POWERED_BY_DISCLOSURE",
            "Application technology is disclosed",
            "The X-Powered-By header exposes framework or runtime information.",
            "Remove the X-Powered-By header.",
            disclosure["x_powered_by"],
        )

    return {
        "security_headers": results,
        "cors": cors_analysis,
        "information_disclosure": disclosure,
    }


def analyze_cookies(
    cookie_headers: list[str],
    final_scheme: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    cookies = []

    for cookie_header in cookie_headers:
        parts = [
            part.strip()
            for part in cookie_header.split(";")
            if part.strip()
        ]

        cookie_name = parts[0].split("=", 1)[0] if parts else "unknown"
        attributes = {part.lower() for part in parts[1:]}

        secure = "secure" in attributes
        http_only = "httponly" in attributes
        same_site = next(
            (
                part.split("=", 1)[1]
                for part in parts[1:]
                if part.lower().startswith("samesite=")
            ),
            None,
        )

        cookie_result = {
            "name": cookie_name,
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site,
        }
        cookies.append(cookie_result)

        if final_scheme == "https" and not secure:
            add_finding(
                findings,
                "medium",
                "COOKIE_SECURE_MISSING",
                f"Cookie {cookie_name} lacks Secure",
                "The cookie may be transmitted over an unencrypted connection.",
                "Add the Secure attribute to cookies used by HTTPS applications.",
                cookie_name,
            )

        if not http_only:
            add_finding(
                findings,
                "medium",
                "COOKIE_HTTPONLY_MISSING",
                f"Cookie {cookie_name} lacks HttpOnly",
                "Client-side JavaScript may be able to access the cookie.",
                "Add HttpOnly when JavaScript access is not required.",
                cookie_name,
            )

        if not same_site:
            add_finding(
                findings,
                "low",
                "COOKIE_SAMESITE_MISSING",
                f"Cookie {cookie_name} lacks SameSite",
                "The cookie has no explicit cross-site request policy.",
                "Set SameSite=Lax or Strict when compatible.",
                cookie_name,
            )

    return {
        "count": len(cookies),
        "cookies": cookies,
    }


def analyze_html(
    content: bytes,
    content_type: str,
    final_url: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    if "html" not in content_type.lower():
        return {
            "analyzed": False,
            "reason": "The final response is not HTML.",
        }

    text = content.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    final_scheme = urlparse(final_url).scheme

    mixed_resources: list[str] = []

    if final_scheme == "https":
        resource_attributes = [
            ("script", "src"),
            ("img", "src"),
            ("iframe", "src"),
            ("link", "href"),
            ("audio", "src"),
            ("video", "src"),
            ("source", "src"),
        ]

        for tag_name, attribute_name in resource_attributes:
            for element in soup.find_all(tag_name):
                resource_url = element.get(attribute_name)

                if (
                    isinstance(resource_url, str)
                    and resource_url.lower().startswith("http://")
                ):
                    mixed_resources.append(resource_url)

    if mixed_resources:
        add_finding(
            findings,
            "high",
            "MIXED_ACTIVE_OR_PASSIVE_CONTENT",
            "HTTP resources loaded from an HTTPS page",
            "The page references resources through unencrypted HTTP.",
            "Serve every page resource through HTTPS.",
            mixed_resources[:10],
        )

    insecure_forms: list[str] = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        absolute_action = urljoin(final_url, action)

        if urlparse(absolute_action).scheme == "http":
            insecure_forms.append(absolute_action)

    if insecure_forms:
        add_finding(
            findings,
            "high",
            "INSECURE_FORM_ACTION",
            "Form submits data through HTTP",
            "At least one form action sends information without HTTPS.",
            "Change all form actions to HTTPS.",
            insecure_forms[:10],
        )

    external_scripts = 0
    scripts_without_integrity = 0

    target_host = urlparse(final_url).hostname

    for script in soup.find_all("script", src=True):
        script_url = urljoin(final_url, script.get("src", ""))
        script_host = urlparse(script_url).hostname

        if script_host and script_host != target_host:
            external_scripts += 1

            if not script.get("integrity"):
                scripts_without_integrity += 1

    if scripts_without_integrity:
        add_finding(
            findings,
            "low",
            "EXTERNAL_SCRIPT_WITHOUT_SRI",
            "External scripts without Subresource Integrity",
            (
                f"{scripts_without_integrity} external script resources do "
                "not declare an integrity attribute."
            ),
            (
                "Use Subresource Integrity for stable third-party scripts "
                "when technically compatible."
            ),
            scripts_without_integrity,
        )

    password_fields = len(
        soup.select('input[type="password"]')
    )

    if password_fields and final_scheme != "https":
        add_finding(
            findings,
            "critical",
            "PASSWORD_FORM_OVER_HTTP",
            "Password field delivered over HTTP",
            "The page contains a password field but is not protected by HTTPS.",
            "Move the complete authentication flow to HTTPS immediately.",
            password_fields,
        )

    generator_meta = soup.find(
        "meta",
        attrs={"name": lambda value: value and value.lower() == "generator"},
    )

    generator = (
        generator_meta.get("content")
        if generator_meta
        else None
    )

    if generator:
        add_finding(
            findings,
            "low",
            "GENERATOR_DISCLOSURE",
            "Application generator is disclosed",
            "The HTML reveals the generator or platform used.",
            "Remove generator metadata if it is not operationally required.",
            generator,
        )

    return {
        "analyzed": True,
        "title": soup.title.string.strip()
        if soup.title and soup.title.string
        else None,
        "password_fields": password_fields,
        "forms": len(soup.find_all("form")),
        "external_scripts": external_scripts,
        "external_scripts_without_sri": scripts_without_integrity,
        "mixed_content_count": len(mixed_resources),
        "insecure_form_count": len(insecure_forms),
        "generator": generator,
    }


def analyze_transport(
    requested_url: str,
    final_url: str,
    redirect_chain: list[dict[str, Any]],
    tls: dict[str, Any] | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    requested_scheme = urlparse(requested_url).scheme
    final_scheme = urlparse(final_url).scheme

    redirects_to_https = (
        requested_scheme == "http"
        and final_scheme == "https"
    )

    if final_scheme != "https":
        add_finding(
            findings,
            "critical",
            "HTTPS_NOT_ENFORCED",
            "Final destination does not use HTTPS",
            "Traffic to the final page is not protected by TLS.",
            "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
            final_url,
        )

    if requested_scheme == "http" and not redirects_to_https:
        add_finding(
            findings,
            "high",
            "HTTP_NOT_REDIRECTED_TO_HTTPS",
            "HTTP does not redirect to HTTPS",
            "The HTTP request did not finish on an HTTPS URL.",
            "Configure a permanent HTTP-to-HTTPS redirect.",
        )

    if tls:
        if not tls.get("available"):
            add_finding(
                findings,
                "critical",
                "TLS_CONNECTION_FAILED",
                "TLS information could not be obtained",
                "The TLS handshake or certificate retrieval failed.",
                "Review certificate deployment and TLS configuration.",
                tls.get("connection_error")
                or tls.get("verification_error"),
            )

        elif not tls.get("trusted"):
            add_finding(
                findings,
                "critical",
                "TLS_CERTIFICATE_UNTRUSTED",
                "TLS certificate is not trusted",
                "Certificate verification failed.",
                "Install a valid certificate from a trusted authority.",
                tls.get("verification_error"),
            )

        days_remaining = tls.get("days_remaining")

        if isinstance(days_remaining, int):
            if days_remaining < 0:
                add_finding(
                    findings,
                    "critical",
                    "TLS_CERTIFICATE_EXPIRED",
                    "TLS certificate has expired",
                    "The certificate validity period has ended.",
                    "Renew and deploy the certificate immediately.",
                    days_remaining,
                )
            elif days_remaining < 7:
                add_finding(
                    findings,
                    "critical",
                    "TLS_CERTIFICATE_EXPIRING_IMMEDIATELY",
                    "TLS certificate expires in less than 7 days",
                    "Certificate expiration is imminent.",
                    "Renew the certificate immediately.",
                    days_remaining,
                )
            elif days_remaining < 30:
                add_finding(
                    findings,
                    "high",
                    "TLS_CERTIFICATE_EXPIRING_SOON",
                    "TLS certificate expires in less than 30 days",
                    "Certificate renewal should be scheduled promptly.",
                    "Renew the certificate and verify automatic renewal.",
                    days_remaining,
                )

        tls_version = tls.get("tls_version")

        if tls_version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            add_finding(
                findings,
                "critical",
                "TLS_VERSION_OBSOLETE",
                "Obsolete TLS protocol negotiated",
                f"The server negotiated {tls_version}.",
                "Disable obsolete protocols and require TLS 1.2 or TLS 1.3.",
                tls_version,
            )

    return {
        "requested_scheme": requested_scheme,
        "final_scheme": final_scheme,
        "https_enabled": final_scheme == "https",
        "http_redirects_to_https": redirects_to_https,
        "redirect_count": max(len(redirect_chain) - 1, 0),
    }


def build_summary(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = Counter(
        finding["severity"]
        for finding in findings
    )

    raw_deduction = sum(
        SEVERITY_DEDUCTION[finding["severity"]]
        for finding in findings
    )

    score = max(0, 100 - min(raw_deduction, 100))

    return {
        "score": score,
        "grade": calculate_grade(score),
        "total_findings": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "risk_level": (
            "critical"
            if counts.get("critical", 0)
            else "high"
            if counts.get("high", 0)
            else "medium"
            if counts.get("medium", 0)
            else "low"
            if counts.get("low", 0)
            else "minimal"
        ),
    }


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "service": "WebSurface QuickScan API",
        "status": "online",
        "version": APP_VERSION,
        "documentation": "/docs",
        "health": "/health",
        "scan_endpoint": "/v1/scan?url=https://example.com",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "version": APP_VERSION,
    }


@app.get("/v1/scan")
async def scan_website(
    url: str = Query(
        ...,
        min_length=10,
        max_length=2048,
        description="Public website URL beginning with http:// or https://",
        examples=["https://example.com"],
    ),
    x_rapidapi_proxy_secret: str | None = Header(
        default=None,
        alias="X-RapidAPI-Proxy-Secret",
    ),
) -> dict[str, Any]:
    validate_rapidapi_proxy_secret(
        x_rapidapi_proxy_secret
    )

    scan_started = time.perf_counter()
    scan_id = str(uuid4())

    try:
        initial_validation = await asyncio.to_thread(
            validate_target_url,
            url,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    fetched = await fetch_target(url)
    final_url = fetched["final_url"]
    parsed_final = urlparse(final_url)
    final_hostname = parsed_final.hostname

    if not final_hostname:
        raise HTTPException(
            status_code=502,
            detail="The final URL does not contain a valid hostname.",
        )

    final_port = (
        parsed_final.port
        or (443 if parsed_final.scheme == "https" else 80)
    )

    tls_information: dict[str, Any] | None = None

    if parsed_final.scheme == "https":
        tls_information = await get_tls_information(
            final_hostname,
            final_port,
        )

    findings: list[dict[str, Any]] = []

    transport_analysis = analyze_transport(
        requested_url=url,
        final_url=final_url,
        redirect_chain=fetched["redirect_chain"],
        tls=tls_information,
        findings=findings,
    )

    header_analysis = analyze_headers(
        headers=fetched["headers"],
        final_scheme=parsed_final.scheme,
        findings=findings,
    )

    cookie_analysis = analyze_cookies(
        cookie_headers=fetched["set_cookie_headers"],
        final_scheme=parsed_final.scheme,
        findings=findings,
    )

    html_analysis = analyze_html(
        content=fetched["content"],
        content_type=fetched["content_type"],
        final_url=final_url,
        findings=findings,
    )

    summary = build_summary(findings)

    total_scan_time_ms = round(
        (time.perf_counter() - scan_started) * 1000,
        2,
    )

    return {
        "scan": {
            "id": scan_id,
            "engine": "WebSurface QuickScan",
            "engine_version": APP_VERSION,
            "scan_type": "passive_configuration_analysis",
            "scanned_at": utc_now_iso(),
            "requested_url": url,
            "final_url": final_url,
            "hostname": final_hostname,
            "status_code": fetched["status_code"],
            "http_version": fetched["http_version"],
            "response_time_ms": fetched["response_time_ms"],
            "total_scan_time_ms": total_scan_time_ms,
        },
        "summary": summary,
        "transport": transport_analysis,
        "tls": tls_information,
        "redirects": fetched["redirect_chain"],
        "headers": header_analysis,
        "cookies": cookie_analysis,
        "html": html_analysis,
        "response_metadata": {
            "content_type": fetched["content_type"],
            "content_encoding": fetched["content_encoding"],
            "body_bytes_analyzed": fetched["body_bytes_analyzed"],
            "body_truncated": fetched["body_truncated"],
            "initial_resolved_ips": initial_validation["resolved_ips"],
            "final_resolved_ips": fetched["resolved_ips"],
        },
        "findings": findings,
        "disclaimer": (
            "This is a passive configuration assessment. It does not perform "
            "exploitation or guarantee that a website is secure. Only assess "
            "systems you are authorized to review."
        ),
    }