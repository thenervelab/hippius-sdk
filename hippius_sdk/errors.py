"""
Custom exceptions for the Hippius SDK.
"""


class HippiusError(Exception):
    """Base exception for all Hippius-specific errors."""

    pass


class HippiusSubstrateError(HippiusError):
    """Base exception for Substrate-related errors."""

    pass


class HippiusAPIError(HippiusError):
    """Base exception for API-related errors."""

    pass


class HippiusArionError(HippiusError):
    """Base exception for Arion storage-related errors."""

    pass


class HippiusAuthenticationError(HippiusAPIError):
    """Raised when there's an authentication issue with the API."""

    pass


class HippiusFailedSubstrateDelete(HippiusSubstrateError):
    """Raised when deletion from blockchain storage fails."""

    pass
