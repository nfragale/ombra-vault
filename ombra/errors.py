"""Custom exception types for Ombra Vault.

Using specific exception types lets the CLI present clean, user-friendly
error messages without leaking implementation details or stack traces.
"""


class OmbraError(Exception):
    """Base class for all Ombra-specific errors."""


class VaultNotFoundError(OmbraError):
    """Raised when a vault file does not exist at the expected path."""


class VaultExistsError(OmbraError):
    """Raised when attempting to initialize a vault that already exists."""


class VaultCorruptedError(OmbraError):
    """Raised when the vault file is malformed or has been tampered with."""


class AuthenticationError(OmbraError):
    """Raised when the master password is incorrect.

    Note: this is also raised on any AES-GCM authentication failure, which
    means it covers both wrong passwords AND silent tampering. We do not
    distinguish between the two to avoid leaking information to attackers.
    """


class EntryNotFoundError(OmbraError):
    """Raised when a credential lookup misses."""


class EntryExistsError(OmbraError):
    """Raised when adding an entry whose service name already exists."""
