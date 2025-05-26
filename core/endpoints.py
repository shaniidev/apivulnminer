"""
Smart Endpoint Discovery Module
Uses pattern recognition to generate likely endpoints
"""

import re
from typing import List, Set, Tuple, Dict
from urllib.parse import urlparse, urljoin
from collections import Counter, defaultdict
from utils.logger import get_logger

logger = get_logger(__name__)

class EndpointDiscovery:
    """Smart endpoint discovery using pattern recognition."""
    
    def __init__(self):
        self.common_patterns = self._load_common_patterns()
        self.resource_patterns = self._load_resource_patterns()
        
    def _load_common_patterns(self) -> Dict[str, List[str]]:
        """Load common API endpoint patterns."""
        return {
            'crud_operations': [
                '{resource}',
                '{resource}/create',
                '{resource}/new',
                '{resource}/edit',
                '{resource}/update',
                '{resource}/delete',
                '{resource}/remove',
                '{resource}/list',
                '{resource}/all',
                '{resource}/search',
                '{resource}/find',
                '{resource}/filter',
                '{resource}/{id}',
                '{resource}/{id}/edit',
                '{resource}/{id}/update',
                '{resource}/{id}/delete',
                '{resource}/{id}/details',
                '{resource}/{id}/view'
            ],
            'nested_resources': [
                '{parent}/{parent_id}/{child}',
                '{parent}/{parent_id}/{child}/create',
                '{parent}/{parent_id}/{child}/{child_id}',
                '{parent}/{parent_id}/{child}/{child_id}/edit',
                '{parent}/{parent_id}/{child}/{child_id}/delete'
            ],
            'api_versioning': [
                'v1/{resource}',
                'v2/{resource}',
                'v3/{resource}',
                'api/v1/{resource}',
                'api/v2/{resource}',
                'api/v3/{resource}',
                'api/{resource}',
                'rest/{resource}',
                'public/{resource}',
                'private/{resource}',
                'internal/{resource}'
            ],
            'file_operations': [
                '{resource}/upload',
                '{resource}/download',
                '{resource}/import',
                '{resource}/export',
                '{resource}/backup',
                '{resource}/restore',
                '{resource}/sync',
                '{resource}/media',
                '{resource}/files',
                '{resource}/attachments'
            ],
            'authentication': [
                'auth/{resource}',
                'oauth/{resource}',
                'sso/{resource}',
                'login/{resource}',
                'register/{resource}',
                'verify/{resource}',
                'reset/{resource}',
                'token/{resource}'
            ]
        }
    
    def _load_resource_patterns(self) -> List[str]:
        """Load common resource naming patterns."""
        return [
            # Singular/Plural variations
            'user', 'users',
            'product', 'products',
            'order', 'orders',
            'customer', 'customers',
            'item', 'items',
            'service', 'services',
            'category', 'categories',
            'tag', 'tags',
            'comment', 'comments',
            'post', 'posts',
            'article', 'articles',
            'page', 'pages',
            'file', 'files',
            'image', 'images',
            'document', 'documents',
            'report', 'reports',
            'invoice', 'invoices',
            'payment', 'payments',
            'subscription', 'subscriptions',
            'notification', 'notifications',
            'message', 'messages',
            'event', 'events',
            'log', 'logs',
            'metric', 'metrics',
            'setting', 'settings',
            'config', 'configs',
            'permission', 'permissions',
            'role', 'roles',
            'group', 'groups',
            'team', 'teams',
            'project', 'projects',
            'task', 'tasks',
            'job', 'jobs',
            'queue', 'queues',
            'session', 'sessions',
            'token', 'tokens',
            'key', 'keys',
            'secret', 'secrets',
            'webhook', 'webhooks',
            'callback', 'callbacks',
            'integration', 'integrations',
            'connection', 'connections',
            'sync', 'syncs',
            'backup', 'backups',
            'restore', 'restores',
            'migration', 'migrations',
            'deployment', 'deployments',
            'release', 'releases',
            'version', 'versions',
            'branch', 'branches',
            'commit', 'commits',
            'diff', 'diffs',
            'merge', 'merges',
            'pull', 'pulls',
            'push', 'pushes',
            'clone', 'clones',
            'fork', 'forks'
        ]
    
    async def generate_smart_endpoints(
        self, 
        discovered_endpoints: Set[str], 
        base_url: str
    ) -> List[Tuple[str, str]]:
        """Generate smart endpoints based on discovered patterns."""
        if not discovered_endpoints:
            return []
        
        logger.info(f"Analyzing {len(discovered_endpoints)} discovered endpoints for patterns")
        
        # Extract patterns from discovered endpoints
        patterns = self._extract_patterns(discovered_endpoints, base_url)
        
        # Generate new endpoints based on patterns
        smart_endpoints = self._generate_from_patterns(patterns, base_url)
        
        # Filter out already discovered endpoints
        new_endpoints = []
        for endpoint, method in smart_endpoints:
            if endpoint not in discovered_endpoints:
                new_endpoints.append((endpoint, method))
        
        logger.info(f"Generated {len(new_endpoints)} smart endpoints")
        return new_endpoints[:100]  # Limit to 100 to avoid overwhelming
    
    def _extract_patterns(self, endpoints: Set[str], base_url: str) -> Dict[str, List[str]]:
        """Extract patterns from discovered endpoints."""
        patterns = {
            'resources': set(),
            'prefixes': set(),
            'suffixes': set(),
            'structures': set(),
            'parameters': set()
        }
        
        for endpoint in endpoints:
            # Remove base URL to get relative path
            relative_path = endpoint.replace(base_url, '').lstrip('/')
            
            if not relative_path:
                continue
            
            # Split path into segments
            segments = [seg for seg in relative_path.split('/') if seg]
            
            if not segments:
                continue
            
            # Extract potential resources (nouns)
            for segment in segments:
                # Clean segment (remove query parameters, file extensions)
                clean_segment = re.sub(r'\?.*$', '', segment)  # Remove query params
                clean_segment = re.sub(r'\.[a-zA-Z0-9]+$', '', clean_segment)  # Remove extensions
                
                # Skip numeric IDs and common non-resource words
                if (not clean_segment.isdigit() and 
                    len(clean_segment) > 2 and 
                    clean_segment not in ['api', 'v1', 'v2', 'v3', 'get', 'post', 'put', 'delete']):
                    patterns['resources'].add(clean_segment)
            
            # Extract path structures
            if len(segments) >= 2:
                structure = '/'.join(['{}'] * len(segments))
                patterns['structures'].add(structure)
            
            # Extract prefixes (first segment)
            if segments:
                patterns['prefixes'].add(segments[0])
            
            # Extract suffixes (last segment if not numeric)
            if segments and not segments[-1].isdigit():
                patterns['suffixes'].add(segments[-1])
        
        # Convert sets to lists for easier processing
        return {k: list(v) for k, v in patterns.items()}
    
    def _generate_from_patterns(
        self, 
        patterns: Dict[str, List[str]], 
        base_url: str
    ) -> List[Tuple[str, str]]:
        """Generate new endpoints from extracted patterns."""
        generated = []
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        # Generate endpoints from discovered resources
        for resource in patterns['resources'][:10]:  # Limit to top 10 resources
            # Generate CRUD operations for each resource
            for pattern_type, pattern_list in self.common_patterns.items():
                for pattern in pattern_list[:5]:  # Limit patterns per type
                    try:
                        endpoint_path = pattern.format(
                            resource=resource,
                            parent=resource,
                            child=self._get_related_resource(resource),
                            parent_id='1',
                            child_id='1',
                            id='1'
                        )
                        
                        full_url = urljoin(base_url.rstrip('/') + '/', endpoint_path)
                        
                        # Add with different HTTP methods
                        for method in methods:
                            generated.append((full_url, method))
                            
                    except (KeyError, ValueError):
                        continue
        
        # Generate variations using discovered prefixes
        for prefix in patterns['prefixes'][:5]:
            for resource in self.resource_patterns[:20]:
                endpoint_path = f"{prefix}/{resource}"
                full_url = urljoin(base_url.rstrip('/') + '/', endpoint_path)
                
                for method in ['GET', 'POST']:
                    generated.append((full_url, method))
        
        # Generate nested resource patterns
        resources = patterns['resources'][:5]
        for i, parent in enumerate(resources):
            for j, child in enumerate(resources):
                if i != j:  # Don't nest resource with itself
                    nested_patterns = [
                        f"{parent}/{child}",
                        f"{parent}/1/{child}",
                        f"{parent}/{child}/1",
                        f"api/{parent}/{child}",
                        f"v1/{parent}/{child}"
                    ]
                    
                    for pattern in nested_patterns:
                        full_url = urljoin(base_url.rstrip('/') + '/', pattern)
                        for method in ['GET', 'POST']:
                            generated.append((full_url, method))
        
        return generated
    
    def _get_related_resource(self, resource: str) -> str:
        """Get a related resource name for nested patterns."""
        # Simple mapping of common resource relationships
        relationships = {
            'user': 'profile',
            'users': 'profiles',
            'product': 'review',
            'products': 'reviews',
            'order': 'item',
            'orders': 'items',
            'customer': 'order',
            'customers': 'orders',
            'post': 'comment',
            'posts': 'comments',
            'article': 'comment',
            'articles': 'comments',
            'category': 'product',
            'categories': 'products',
            'project': 'task',
            'projects': 'tasks',
            'team': 'member',
            'teams': 'members'
        }
        
        return relationships.get(resource.lower(), 'item')
    
    def analyze_endpoint_patterns(self, endpoints: Set[str]) -> Dict[str, any]:
        """Analyze patterns in discovered endpoints for reporting."""
        analysis = {
            'total_endpoints': len(endpoints),
            'unique_resources': set(),
            'common_prefixes': Counter(),
            'common_suffixes': Counter(),
            'path_depths': Counter(),
            'file_extensions': Counter(),
            'http_methods_likely': set(),
            'api_versions': set(),
            'authentication_endpoints': [],
            'admin_endpoints': [],
            'file_endpoints': [],
            'potential_vulnerabilities': []
        }
        
        for endpoint in endpoints:
            # Parse URL
            parsed = urlparse(endpoint)
            path = parsed.path.strip('/')
            
            if not path:
                continue
            
            segments = path.split('/')
            
            # Analyze path depth
            analysis['path_depths'][len(segments)] += 1
            
            # Extract prefixes and suffixes
            if segments:
                analysis['common_prefixes'][segments[0]] += 1
                analysis['common_suffixes'][segments[-1]] += 1
            
            # Look for file extensions
            if '.' in segments[-1]:
                ext = segments[-1].split('.')[-1]
                analysis['file_extensions'][ext] += 1
            
            # Identify API versions
            for segment in segments:
                if re.match(r'^v\d+$', segment):
                    analysis['api_versions'].add(segment)
            
            # Identify endpoint types
            path_lower = path.lower()
            
            if any(auth_term in path_lower for auth_term in ['auth', 'login', 'token', 'oauth']):
                analysis['authentication_endpoints'].append(endpoint)
            
            if any(admin_term in path_lower for admin_term in ['admin', 'manage', 'control']):
                analysis['admin_endpoints'].append(endpoint)
            
            if any(file_term in path_lower for file_term in ['upload', 'download', 'file', 'media']):
                analysis['file_endpoints'].append(endpoint)
            
            # Look for potential vulnerabilities
            if any(vuln_term in path_lower for vuln_term in ['debug', 'test', 'dev', 'staging']):
                analysis['potential_vulnerabilities'].append({
                    'endpoint': endpoint,
                    'type': 'debug_endpoint',
                    'description': 'Potential debug or development endpoint'
                })
        
        return analysis 