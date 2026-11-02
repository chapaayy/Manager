"""Validate cert.status data produced by the node Agent."""
from __future__ import annotations

from email.utils import parsedate_to_datetime
import re
import time

from ... import storage
from .errors import LocalTLSError


def agent_status(node_id: str, data: dict):
    node = storage.get_node(node_id)
    if node["status"] != "ready" or data.get("domain") != node["domain"]:
        raise LocalTLSError("Нода или домен в отчёте агента не совпадают")
    if any(key in data for key in ("key", "chain", "certificate")):
        raise LocalTLSError(
            "Передача PEM в режиме локальных TLS запрещена"
        )
    fingerprint = data.get("certificate_sha256")
    details = data.get("details")
    if not isinstance(fingerprint, str) or not re.fullmatch(
        "[0-9a-f]{64}", fingerprint
    ):
        raise LocalTLSError("Агент не подтвердил отпечаток сертификата")
    if data.get("node_tls_mount_verified") is False:
        raise LocalTLSError(
            "Агент не подтвердил файловые сертификаты внутри Xray"
        )
    if (
        not isinstance(details, str)
        or len(details) > 500
        or "notAfter=" not in details
    ):
        raise LocalTLSError(
            "Агент не подтвердил срок действия сертификата"
        )
    try:
        expires = int(
            parsedate_to_datetime(
                details.split("notAfter=", 1)[1].splitlines()[0]
            ).timestamp()
        )
    except (ValueError, TypeError, OverflowError, IndexError):
        raise LocalTLSError(
            "Невозможно прочитать срок действия TLS"
        ) from None
    if expires < int(time.time()) + 3600:
        raise LocalTLSError(
            "TLS сертификат просрочен или скоро истечёт"
        )
    return node, fingerprint, expires
