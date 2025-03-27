"""
Provider registry for PyASN data sources
"""

from typing import Dict, Type, Any

class ProviderRegistry:
    """Registry for data provider classes"""
    _providers: Dict[str, Type] = {}
    
    @classmethod
    def register(cls, provider_type: str, provider_name: str, provider_class: Type):
        """
        Register a provider class
        
        Args:
            provider_type: Type of provider (e.g., 'asn', 'ip', 'geo')
            provider_name: Name of the provider
            provider_class: Provider class
        """
        if provider_type not in cls._providers:
            cls._providers[provider_type] = {}
        
        cls._providers[provider_type][provider_name] = provider_class
    
    @classmethod
    def get_provider(cls, provider_type: str, provider_name: str) -> Type:
        """
        Get a provider class by type and name
        
        Args:
            provider_type: Type of provider
            provider_name: Name of the provider
            
        Returns:
            Provider class
            
        Raises:
            KeyError: If provider is not registered
        """
        if provider_type not in cls._providers or provider_name not in cls._providers[provider_type]:
            raise KeyError(f"Provider not found: {provider_type}/{provider_name}")
        
        return cls._providers[provider_type][provider_name]
    
    @classmethod
    def get_providers_by_type(cls, provider_type: str) -> Dict[str, Type]:
        """
        Get all providers of a specific type
        
        Args:
            provider_type: Type of provider
            
        Returns:
            Dictionary of provider names to provider classes
        """
        return cls._providers.get(provider_type, {})