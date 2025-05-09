"""
Custom exceptions for the Hippius SDK.
"""


class HippiusError(Exception):
    """Base exception for all Hippius-specific errors."""

    pass


class HippiusSubstrateError(HippiusError):
    """Base exception for Substrate-related errors."""

    pass


class HippiusIPFSError(HippiusError):
    """Base exception for IPFS-related errors."""

    pass


# Specific blockchain errors
class HippiusNotFoundError(HippiusSubstrateError):
    """Raised when a resource is not found on the blockchain."""

    pass


class HippiusAlreadyDeletedError(HippiusSubstrateError):
    """Raised when trying to delete a file that's already deleted from the blockchain."""

    pass


class HippiusSubstrateConnectionError(HippiusSubstrateError):
    """Raised when there's an issue connecting to the Substrate node."""

    pass


class HippiusSubstrateAuthError(HippiusSubstrateError):
    """Raised when there's an authentication issue with the Substrate client."""

    pass


class HippiusFailedSubstrateDelete(HippiusSubstrateError):
    """Raised when deletion from blockchain storage fails."""

    pass


# IPFS-specific errors
class HippiusIPFSConnectionError(HippiusIPFSError):
    """Raised when there's an issue connecting to IPFS."""

    pass


class HippiusFailedIPFSUnpin(HippiusIPFSError):
    """Raised when unpinning from IPFS fails."""

    pass


class HippiusMetadataError(HippiusIPFSError):
    """Raised when there's an issue with the metadata file."""

    pass


class HippiusInvalidCIDError(HippiusIPFSError):
    """Raised when an invalid CID is provided."""

    pass
