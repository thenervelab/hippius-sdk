"""
Shared HTTP utilities for the Hippius SDK.

Provides a unified retry decorator and httpx client factory used by
both ArionClient and HippiusApiClient.
"""

import asyncio
import functools
import logging
from typing import Any, Callable, Coroutine, Set, TypeVar

import httpx

from hippius_sdk.errors import HippiusAuthenticationError

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default HTTP status codes that should not be retried
DEFAULT_NON_RETRYABLE_CODES: Set[int] = {401, 403, 404, 507}


def retry_on_error(
    retries: int = 3,
    backoff: float = 5.0,
    non_retryable_codes: Set[int] | None = None,
    base_error_class: type[Exception] = Exception,
) -> Callable[[Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]]:
    """
    Decorator to retry HTTP requests on 4xx/5xx errors.

    Args:
        retries: Number of retry attempts (default: 3)
        backoff: Seconds to wait between retries (default: 5.0)
        non_retryable_codes: HTTP status codes that should not be retried
                             (default: {401, 403, 404, 507})
        base_error_class: The base exception class to catch alongside httpx errors
    """
    if non_retryable_codes is None:
        non_retryable_codes = DEFAULT_NON_RETRYABLE_CODES

    def decorator(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Exception | None = None

            for attempt in range(retries + 1):
                try:
                    return await func(*args, **kwargs)
                except (httpx.HTTPStatusError, base_error_class) as e:
                    last_exception = e

                    if hasattr(e, "response"):
                        status = e.response.status_code

                        # Convert auth errors
                        if status in (401, 403):
                            raise HippiusAuthenticationError(
                                f"Authentication failed: {e}"
                            ) from None

                        # Don't retry non-retryable codes
                        if status in non_retryable_codes:
                            raise

                    # Don't retry if this was the last attempt
                    if attempt == retries:
                        break

                    func_name = func.__name__
                    error_msg = f"Request failed (attempt {attempt + 1}/{retries + 1}): {e}"
                    error_msg += f" | Function: {func_name}"
                    if hasattr(e, "response"):
                        error_msg += f" | Response body: {e.response.text}"
                    logger.error(error_msg)
                    await asyncio.sleep(backoff)
                except Exception:
                    # Don't retry on unexpected errors
                    raise

            # If we get here, all retries failed
            if last_exception is not None:
                raise last_exception
            raise RuntimeError("All retries failed with no exception captured")

        return wrapper

    return decorator


def create_http_client(base_url: str) -> httpx.AsyncClient:
    """
    Create a configured httpx.AsyncClient with standard timeout and redirect settings.

    Args:
        base_url: The base URL for the HTTP client

    Returns:
        httpx.AsyncClient: Configured HTTP client
    """
    return httpx.AsyncClient(
        base_url=base_url,
        timeout=httpx.Timeout(60.0, connect=10.0),
        follow_redirects=True,
    )
