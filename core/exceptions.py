"""
Custom exceptions for PyASN
"""

class PyASNError(Exception):
    """Base exception for all PyASN errors"""
    pass

class ConfigurationError(PyASNError):
    """Error in configuration settings"""
    pass

class NetworkError(PyASNError):
    """Network connectivity issues"""
    def __init__(self, message, service=None):
        self.service = service
        super().__init__(message)

class APIError(PyASNError):
    """Errors from external APIs"""
    def __init__(self, service, message, status_code=None):
        self.service = service
        self.status_code = status_code
        super().__init__(f"{service} API error: {message}")

class DataParsingError(PyASNError):
    """Error parsing data from external sources"""
    def __init__(self, message, source=None):
        self.source = source
        super().__init__(message)

class LookupError(PyASNError):
    """Error during lookup operations"""
    pass

class ValidationError(PyASNError):
    """Error validating input data"""
    pass

class AuthenticationError(PyASNError):
    """Error authenticating with external services"""
    def __init__(self, service):
        self.service = service
        super().__init__(f"Authentication failed for {service}")

class RateLimitError(APIError):
    """Rate limit exceeded for an API"""
    def __init__(self, service, retry_after=None):
        self.retry_after = retry_after
        message = f"Rate limit exceeded for {service}"
        if retry_after:
            message += f", retry after {retry_after} seconds"
        super().__init__(service, message)