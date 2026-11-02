class TLSError(ValueError):
    """Base error for node-local TLS operations."""


class CertificateSyncError(TLSError):
    """Manager/API-facing TLS synchronization error."""


class LocalTLSError(TLSError):
    """Validated node-local TLS state or migration error."""
