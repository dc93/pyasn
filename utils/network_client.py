"""
PyASN Network Client - A robust HTTP client for making API requests

This module provides both synchronous and asynchronous HTTP clients with consistent
error handling, retries, timeouts, and logging for the PyASN application.

Dependencies:
- requests
- aiohttp (for async operations)
- backoff (for retry mechanisms)
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union, cast
from urllib.parse import urljoin

import backoff
import requests

# Optional import for async functionality
try:
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

from pyasn.core.exceptions import (
    APIError,
    NetworkError,
    DataParsingError,
    RateLimitError,
    ValidationError
)

logger = logging.getLogger(__name__)

class APIConfig:
    """Configuration for API client"""
    
    def __init__(
        self,
        base_url: str = "",
        timeout: int = 10,
        max_retries: int = 3,
        retry_backoff_factor: float = 0.5,
        retry_status_codes: Tuple[int, ...] = (408, 429, 500, 502, 503, 504),
        verify_ssl: bool = True,
        user_agent: str = "PyASN/1.0.0",
        source_app: str = "pyasn",
    ):
        """
        Initialize API configuration
        
        Args:
            base_url: Base URL for API requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries
            retry_backoff_factor: Backoff factor for retries
            retry_status_codes: Status codes to retry
            verify_ssl: Whether to verify SSL certificates
            user_agent: User agent string
            source_app: Source application name
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff_factor = retry_backoff_factor
        self.retry_status_codes = retry_status_codes
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.source_app = source_app


class NetworkClient:
    """Synchronized HTTP client for making API requests"""
    
    def __init__(self, config: Optional[APIConfig] = None):
        """
        Initialize network client
        
        Args:
            config: API configuration
        """
        self.config = config or APIConfig()
        
        # Set up session
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})
        
        # Create requests adapter with retries
        adapter = requests.adapters.HTTPAdapter(
            max_retries=self.config.max_retries
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def __enter__(self):
        """Support context manager protocol"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close session when exiting context"""
        self.close()
    
    def close(self):
        """Close the session"""
        self.session.close()
    
    @backoff.on_exception(
        backoff.expo,
        (requests.exceptions.Timeout, requests.exceptions.ConnectionError),
        max_tries=3,
        giveup=lambda e: isinstance(e, requests.exceptions.HTTPError)
    )
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        raw_response: bool = False,
    ) -> Any:
        """
        Perform a GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout override
            raw_response: Whether to return the raw response object
            
        Returns:
            Response data (usually parsed JSON) or raw response if requested
            
        Raises:
            NetworkError: For connection and timeout issues
            APIError: For API errors (4xx, 5xx)
            DataParsingError: For JSON parsing errors
            RateLimitError: For rate limiting (429)
        """
        full_url = urljoin(self.config.base_url, url) if self.config.base_url else url
        request_timeout = timeout or self.config.timeout
        
        # Add sourceapp parameter if not already present
        if params is None:
            params = {}
        if "sourceapp" not in params:
            params["sourceapp"] = self.config.source_app
        
        try:
            start_time = time.time()
            response = self.session.get(
                full_url,
                params=params,
                headers=headers,
                timeout=request_timeout,
                verify=self.config.verify_ssl,
            )
            elapsed = time.time() - start_time
            
            logger.debug(f"GET {full_url} completed in {elapsed:.3f}s with status {response.status_code}")
            
            # Check for rate limiting
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        retry_after = int(retry_after)
                    except (ValueError, TypeError):
                        retry_after = None
                raise RateLimitError(self._get_service_name(url), retry_after)
            
            # Raise for other HTTP errors
            response.raise_for_status()
            
            if raw_response:
                return response
                
            # Parse JSON response
            try:
                data = response.json()
                return data
            except ValueError as e:
                # If the response is supposed to be JSON but isn't, this is an error
                # Check if the content is very short (like "No information available")
                if len(response.text) < 100:
                    # This might be an expected non-JSON response
                    logger.debug(f"Non-JSON response received: {response.text}")
                    return {"text": response.text, "status_code": response.status_code}
                raise DataParsingError(f"Failed to parse JSON response: {e}", self._get_service_name(url))
                
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request to {url} timed out after {request_timeout}s")
            raise NetworkError(f"Request timed out: {e}", self._get_service_name(url))
            
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error for {url}: {e}")
            raise NetworkError(f"Connection error: {e}", self._get_service_name(url))
            
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') else None
            logger.warning(f"HTTP error for {url}: {e} (status: {status_code})")
            raise APIError(self._get_service_name(url), f"HTTP error: {e}", status_code)
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error for {url}: {e}")
            raise NetworkError(f"Request failed: {e}", self._get_service_name(url))
    
    def _get_service_name(self, url: str) -> str:
        """
        Extract service name from URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Service name
        """
        # Try to extract the domain from the URL
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            # Return first part of domain (e.g., "api" from "api.example.com")
            service = domain.split('.')[0]
            if service in ('www', 'api'):
                service = domain.split('.')[1]
            return service.upper()
        except Exception:
            # Fallback to a generic name
            return "API"


class AsyncNetworkClient:
    """Asynchronous HTTP client for making API requests"""
    
    def __init__(self, config: Optional[APIConfig] = None):
        """
        Initialize async network client
        
        Args:
            config: API configuration
            
        Raises:
            ImportError: If aiohttp is not installed
        """
        if not ASYNC_AVAILABLE:
            raise ImportError(
                "aiohttp is required for async operations. "
                "Install it with 'pip install aiohttp'."
            )
            
        self.config = config or APIConfig()
        self.session = None
    
    async def __aenter__(self):
        """Support async context manager protocol"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                headers={"User-Agent": self.config.user_agent}
            )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close session when exiting context"""
        await self.close()
    
    async def close(self):
        """Close the session if it exists"""
        if self.session is not None:
            await self.session.close()
            self.session = None
    
    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError),
        max_tries=3
    )
    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        raw_response: bool = False,
    ) -> Any:
        """
        Perform an asynchronous GET request
        
        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout override
            raw_response: Whether to return the raw response object
            
        Returns:
            Response data (usually parsed JSON) or raw response if requested
            
        Raises:
            NetworkError: For connection and timeout issues
            APIError: For API errors (4xx, 5xx)
            DataParsingError: For JSON parsing errors
            RateLimitError: For rate limiting (429)
        """
        # Initialize session if needed, with lock to prevent race conditions
        if self.session is None:
            # Use a class attribute lock if this is called concurrently
            if not hasattr(self.__class__, '_session_init_lock'):
                self.__class__._session_init_lock = asyncio.Lock()
            
            async with self.__class__._session_init_lock:
                # Check again in case another task initialized it while we were waiting
                if self.session is None:
                    self.session = aiohttp.ClientSession(
                        headers={"User-Agent": self.config.user_agent}
                    )
            
        full_url = urljoin(self.config.base_url, url) if self.config.base_url else url
        request_timeout = aiohttp.ClientTimeout(total=timeout or self.config.timeout)
        
        # Add sourceapp parameter if not already present
        if params is None:
            params = {}
        if "sourceapp" not in params:
            params["sourceapp"] = self.config.source_app
        
        try:
            start_time = time.time()
            async with self.session.get(
                full_url,
                params=params,
                headers=headers,
                timeout=request_timeout,
                ssl=None if self.config.verify_ssl else False,
            ) as response:
                elapsed = time.time() - start_time
                logger.debug(f"Async GET {full_url} completed in {elapsed:.3f}s with status {response.status}")
                
                # Check for rate limiting
                if response.status == 429:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            retry_after = int(retry_after)
                        except (ValueError, TypeError):
                            retry_after = None
                    raise RateLimitError(self._get_service_name(url), retry_after)
                
                # Raise for other HTTP errors
                response.raise_for_status()
                
                if raw_response:
                    return response
                
                # Parse JSON response
                try:
                    data = await response.json()
                    return data
                except ValueError as e:
                    # If the response is supposed to be JSON but isn't
                    text = await response.text()
                    if len(text) < 100:
                        # This might be an expected non-JSON response
                        logger.debug(f"Non-JSON response received: {text}")
                        return {"text": text, "status_code": response.status}
                    raise DataParsingError(f"Failed to parse JSON response: {e}", self._get_service_name(url))
                    
        except asyncio.TimeoutError as e:
            logger.warning(f"Async request to {url} timed out")
            raise NetworkError(f"Request timed out: {e}", self._get_service_name(url))
            
        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Async connection error for {url}: {e}")
            raise NetworkError(f"Connection error: {e}", self._get_service_name(url))
            
        except aiohttp.ClientResponseError as e:
            logger.warning(f"Async HTTP error for {url}: {e}")
            raise APIError(self._get_service_name(url), f"HTTP error: {e}", e.status)
            
        except aiohttp.ClientError as e:
            logger.warning(f"Async request error for {url}: {e}")
            raise NetworkError(f"Request failed: {e}", self._get_service_name(url))
    
    def _get_service_name(self, url: str) -> str:
        """
        Extract service name from URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Service name
        """
        # Try to extract the domain from the URL
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            # Return first part of domain (e.g., "api" from "api.example.com")
            service = domain.split('.')[0]
            if service in ('www', 'api'):
                service = domain.split('.')[1]
            return service.upper()
        except Exception:
            # Fallback to a generic name
            return "API"


def create_network_client(
    config: Optional[APIConfig] = None,
    async_client: bool = False
) -> Union[NetworkClient, AsyncNetworkClient]:
    """
    Factory function to create a network client
    
    Args:
        config: API configuration
        async_client: Whether to create an async client
        
    Returns:
        Network client instance
        
    Raises:
        ImportError: If aiohttp is not installed and async_client is True
    """
    if async_client:
        if not ASYNC_AVAILABLE:
            raise ImportError(
                "aiohttp is required for async operations. "
                "Install it with 'pip install aiohttp'."
            )
        return AsyncNetworkClient(config)
    return NetworkClient(config)