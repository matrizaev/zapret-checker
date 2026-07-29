#!/usr/bin/env python3
"""Download the RKN blacklist and social-resource XML dumps over SOAP.

The service requires a detached PKCS#7 signature of the operator request.
This script uses the ``rutoken-sign`` helper built by this repository.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import io
import logging
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET


SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
SERVICE_NS = "http://vigruzki.rkn.gov.ru/OperatorRequest/"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XSD_NS = "http://www.w3.org/2001/XMLSchema"
SOAP_ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"

LOG = logging.getLogger("rkn-soap")


class SoapError(RuntimeError):
    """A SOAP response or service-level error."""


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child_text(element: ET.Element, *names: str, required: bool = True) -> str | None:
    wanted = set(names)
    for child in element.iter():
        if local_name(child.tag) in wanted and child.text is not None:
            value = child.text.strip()
            if value:
                return value
    if required:
        raise SoapError(f"SOAP response is missing {', '.join(names)}")
    return None


def response_element(payload: bytes, expected: Iterable[str]) -> ET.Element:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise SoapError(f"invalid SOAP XML: {exc}") from exc

    fault = next((node for node in root.iter() if local_name(node.tag) == "Fault"), None)
    if fault is not None:
        reason = child_text(fault, "faultstring", "Text", required=False)
        raise SoapError(f"SOAP fault: {reason or 'unknown fault'}")

    expected_set = set(expected)
    result = next(
        (node for node in root.iter() if local_name(node.tag) in expected_set),
        None,
    )
    if result is None:
        raise SoapError(f"SOAP response does not contain {', '.join(expected_set)}")
    return result


def make_envelope(method: str, values: Iterable[tuple[str, str, str]] = ()) -> bytes:
    ET.register_namespace("soap", SOAP_ENV)
    ET.register_namespace("tns", SERVICE_NS)
    ET.register_namespace("xsi", XSI_NS)
    ET.register_namespace("xsd", XSD_NS)

    envelope = ET.Element(
        f"{{{SOAP_ENV}}}Envelope",
        {
            f"{{{SOAP_ENV}}}encodingStyle": SOAP_ENCODING,
            "xmlns:xsd": XSD_NS,
        },
    )
    body = ET.SubElement(envelope, f"{{{SOAP_ENV}}}Body")
    call = ET.SubElement(body, f"{{{SERVICE_NS}}}{method}")
    if method == "getLastDumpDateEx":
        call.set(f"{{{XSI_NS}}}nil", "true")
    for name, value, xsd_type in values:
        node = ET.SubElement(call, name)
        node.set(f"{{{XSI_NS}}}type", f"xsd:{xsd_type}")
        node.text = value
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


class SoapClient:
    def __init__(self, host: str, timeout: float) -> None:
        host = host.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        if not host:
            raise ValueError("SOAP host cannot be empty")
        self.host = host
        self.url = f"https://{host}/services/OperatorRequest/"
        self.timeout = timeout

    def call(self, method: str, values: Iterable[tuple[str, str, str]] = ()) -> bytes:
        body = make_envelope(method, values)
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Accept": "application/soap; text/xml",
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": f'"{self.url}{method}"',
                "Connection": "close",
            },
        )
        LOG.info("SOAP: %s", method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise SoapError(f"{method}: HTTP {exc.code}: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise SoapError(f"{method}: {exc.reason}") from exc


def load_configuration(path: Path) -> tuple[str, ET.Element, str | None, str | None]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise SoapError(f"cannot read configuration {path}: {exc}") from exc

    rkn = next((node for node in root.iter() if local_name(node.tag) == "rknBlacklist"), None)
    if rkn is None:
        raise SoapError(f"{path} has no rknBlacklist section")

    host = child_text(rkn, "host")
    request = next(
        (node for node in list(rkn) if local_name(node.tag) == "request"),
        None,
    )
    if request is None:
        raise SoapError(f"{path} has no rknBlacklist/request section")

    key = next(
        (node for node in list(rkn) if local_name(node.tag) == "privateKey"),
        None,
    )
    key_id = key.text.strip() if key is not None and key.text else None
    pin = key.get("password") if key is not None else None
    return host, request, key_id, pin


def build_operator_request(template: ET.Element) -> bytes:
    request = ET.fromstring(ET.tostring(template, encoding="utf-8"))
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S.000%z")
    time_node = next(
        (node for node in request.iter() if local_name(node.tag) == "requestTime"),
        None,
    )
    if time_node is None:
        raise SoapError("operator request has no requestTime element")
    time_node.text = timestamp
    return ET.tostring(
        request,
        encoding="windows-1251",
        xml_declaration=True,
        short_empty_elements=True,
    )


def sign_with_rutoken(
    request_bytes: bytes,
    signer: Path,
    pin: str,
    key_id: str,
    slot: int,
) -> bytes:
    if not signer.is_file():
        raise SoapError(f"Rutoken signer does not exist: {signer}")

    with tempfile.TemporaryDirectory(prefix="rkn-soap-") as temp_dir:
        request_path = Path(temp_dir) / "request.xml"
        request_path.write_bytes(request_bytes)
        command = [str(signer), str(request_path), pin, key_id, str(slot)]
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.decode(errors="replace").strip()
            raise SoapError(f"Rutoken signing failed: {detail or exc}") from exc
        signature_path = Path(f"{request_path}.sign")
        try:
            signature = signature_path.read_bytes()
        except OSError as exc:
            raise SoapError(f"Rutoken signer did not create {signature_path}") from exc
        if not signature:
            raise SoapError("Rutoken signer produced an empty signature")
        return signature


def save_xml_archive(encoded_archive: str, destination: Path) -> None:
    try:
        compact_archive = "".join(encoded_archive.split())
        archive = base64.b64decode(compact_archive, validate=True)
    except ValueError as exc:
        raise SoapError(f"{destination.name}: invalid base64 archive") from exc

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            candidates = [
                info
                for info in zipped.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".xml")
            ]
            if not candidates:
                raise SoapError(f"{destination.name}: ZIP archive contains no XML file")
            preferred = next(
                (info for info in candidates if Path(info.filename).name.lower() == "dump.xml"),
                candidates[0],
            )
            xml_data = zipped.read(preferred)
    except zipfile.BadZipFile as exc:
        raise SoapError(f"{destination.name}: service returned an invalid ZIP archive") from exc

    try:
        ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise SoapError(f"{destination.name}: extracted data is not valid XML: {exc}") from exc

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(xml_data)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    LOG.info("Saved %s (%d bytes)", destination, len(xml_data))


def download(args: argparse.Namespace) -> None:
    host, request_template, config_key_id, config_pin = load_configuration(args.config)
    host = args.host or host
    key_id = args.key_id or config_key_id
    pin = args.pin or config_pin
    if not key_id:
        raise SoapError("private key ID is missing (use --key-id or configure privateKey)")
    if pin is None:
        pin = getpass.getpass("Rutoken PIN: ")

    client = SoapClient(host, args.timeout)
    metadata = response_element(
        client.call("getLastDumpDateEx"),
        ("getLastDumpDateExResponse",),
    )
    dump_format = child_text(metadata, "dumpFormatVersion")

    request_bytes = build_operator_request(request_template)
    signature = sign_with_rutoken(
        request_bytes,
        args.signer.resolve(),
        pin,
        key_id,
        args.slot,
    )
    submitted = response_element(
        client.call(
            "sendRequest",
            (
                ("requestFile", base64.b64encode(request_bytes).decode("ascii"), "base64Binary"),
                ("signatureFile", base64.b64encode(signature).decode("ascii"), "base64Binary"),
                ("dumpFormatVersion", dump_format, "string"),
            ),
        ),
        ("sendRequestResponse",),
    )
    accepted = child_text(submitted, "result").lower()
    request_code = child_text(submitted, "code")
    comment = child_text(submitted, "resultComment", required=False)
    if accepted not in {"true", "1"}:
        raise SoapError(f"sendRequest was rejected: {comment or 'no explanation'}")
    LOG.info("Request accepted; code=%s", request_code)

    blacklist_archive = None
    last_comment = None
    for attempt in range(1, args.poll_count + 1):
        if attempt > 1 or args.poll_interval:
            LOG.info("Waiting %.1f seconds for result (%d/%d)", args.poll_interval, attempt, args.poll_count)
            time.sleep(args.poll_interval)
        result = response_element(
            client.call("getResult", (("code", request_code, "string"),)),
            ("getResultResponse",),
        )
        result_code_text = child_text(result, "resultCode", required=False) or "0"
        try:
            result_code = int(result_code_text)
        except ValueError as exc:
            raise SoapError(f"invalid resultCode: {result_code_text!r}") from exc
        last_comment = child_text(result, "resultComment", required=False)
        if result_code == 1:
            blacklist_archive = child_text(result, "registerZipArchive")
            break
        if result_code < 0:
            raise SoapError(f"getResult failed with code {result_code}: {last_comment or ''}")
    if blacklist_archive is None:
        raise SoapError(f"result was not ready after {args.poll_count} attempts: {last_comment or ''}")

    social = response_element(
        client.call(
            "getResultSocResources",
            (("code", request_code, "string"),),
        ),
        ("getResultSocResourcesResponse", "getResultResponse"),
    )
    social_archive = child_text(
        social,
        "registerZipArchive",
        "registerZipArchiveSocResources",
        "socialZipArchive",
    )

    save_xml_archive(blacklist_archive, args.output_dir / "blacklist.xml")
    save_xml_archive(social_archive, args.output_dir / "social.xml")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Download blacklist.xml and social.xml from the RKN SOAP service.",
    )
    result.add_argument(
        "--config",
        type=Path,
        default=Path("zapret-checker.xml"),
        help="zapret-checker XML configuration (default: %(default)s)",
    )
    result.add_argument("--host", help="override the SOAP host from the configuration")
    result.add_argument(
        "--signer",
        type=Path,
        default=Path("./rutoken-sign"),
        help="path to the repository's rutoken-sign executable (default: %(default)s)",
    )
    result.add_argument("--key-id", help="override the private-key ID from the configuration")
    result.add_argument(
        "--pin",
        help="override the Rutoken PIN (prefer the config or interactive prompt)",
    )
    result.add_argument("--slot", type=int, default=0, help="Rutoken slot index (default: 0)")
    result.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="directory for blacklist.xml and social.xml (default: current directory)",
    )
    result.add_argument("--timeout", type=float, default=60, help="HTTP timeout in seconds")
    result.add_argument(
        "--poll-interval",
        type=float,
        default=10,
        help="seconds between getResult calls (default: 10)",
    )
    result.add_argument(
        "--poll-count",
        type=int,
        default=50,
        help="maximum getResult calls (default: 50)",
    )
    result.add_argument("-v", "--verbose", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.slot < 0 or args.poll_count < 1 or args.poll_interval < 0:
        parser().error("slot and poll interval must be non-negative; poll count must be positive")
    try:
        download(args)
    except (SoapError, OSError) as exc:
        LOG.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
