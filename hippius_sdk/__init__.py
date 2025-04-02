"""
Hippius SDK - Python interface for Hippius blockchain storage
"""

from hippius_sdk.client import HippiusClient
from hippius_sdk.ipfs import IPFSClient

__version__ = "0.1.0"
__all__ = ["HippiusClient", "IPFSClient"]

# Note: Substrate functionality will be added in a future release
