"""
Wordlist Management Module
Handles loading and managing API endpoint wordlists
"""

import asyncio
from pathlib import Path
from typing import List, Set
from utils.logger import get_logger

logger = get_logger(__name__)

class WordlistManager:
    """Manages wordlists for API endpoint discovery."""
    
    def __init__(self):
        self.default_wordlist = self._get_default_api_wordlist()
        
    def _get_default_api_wordlist(self) -> List[str]:
        """Get default API endpoint wordlist."""
        return [
            # Common API endpoints
            "api", "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
            
            # Authentication & Authorization
            "auth", "login", "logout", "signin", "signup", "register",
            "token", "refresh", "oauth", "sso", "verify", "reset",
            "password", "forgot", "activate", "confirm",
            
            # User Management
            "users", "user", "profile", "account", "accounts",
            "me", "settings", "preferences", "dashboard",
            
            # CRUD Operations
            "create", "read", "update", "delete", "list", "get",
            "post", "put", "patch", "remove", "edit", "modify",
            
            # Data Endpoints
            "data", "info", "details", "status", "health", "ping",
            "version", "config", "configuration", "metadata",
            
            # File Operations
            "upload", "download", "file", "files", "media", "image",
            "images", "document", "documents", "attachment", "assets",
            
            # Search & Filtering
            "search", "find", "filter", "query", "lookup", "browse",
            "explore", "discover", "suggest", "autocomplete",
            
            # Admin Functions
            "admin", "administrator", "management", "manage", "control",
            "panel", "console", "dashboard", "monitor", "logs",
            
            # Common Resources
            "products", "product", "items", "item", "orders", "order",
            "customers", "customer", "clients", "client", "services",
            "service", "categories", "category", "tags", "tag",
            
            # API Documentation
            "docs", "documentation", "help", "guide", "reference",
            "swagger", "openapi", "schema", "spec", "api-docs",
            
            # Webhooks & Events
            "webhook", "webhooks", "events", "event", "notifications",
            "notify", "callback", "callbacks", "subscribe", "unsubscribe",
            
            # Analytics & Reporting
            "analytics", "stats", "statistics", "metrics", "reports",
            "report", "insights", "tracking", "monitor", "audit",
            
            # Payment & Billing
            "payment", "payments", "billing", "invoice", "invoices",
            "subscription", "subscriptions", "checkout", "cart",
            
            # Social Features
            "comments", "comment", "likes", "like", "share", "follow",
            "followers", "following", "friends", "messages", "chat",
            
            # Content Management
            "content", "posts", "post", "articles", "article", "pages",
            "page", "blog", "news", "feed", "timeline",
            
            # Location & Geography
            "location", "locations", "address", "addresses", "geo",
            "coordinates", "map", "maps", "places", "regions",
            
            # Time & Scheduling
            "schedule", "calendar", "events", "appointments", "booking",
            "reservations", "availability", "slots", "time", "date",
            
            # Security & Permissions
            "permissions", "roles", "role", "access", "security",
            "policy", "policies", "rules", "acl", "rbac",
            
            # Integration Endpoints
            "integration", "integrations", "connect", "sync", "import",
            "export", "backup", "restore", "migrate", "transfer",
            
            # Mobile & Device
            "mobile", "device", "devices", "app", "apps", "push",
            "notifications", "fcm", "apns", "registration",
            
            # Testing & Development
            "test", "testing", "debug", "dev", "development", "staging",
            "sandbox", "mock", "demo", "sample", "example",
            
            # Common HTTP Methods as Endpoints
            "get", "post", "put", "delete", "patch", "options", "head",
            
            # Database-like Endpoints
            "db", "database", "table", "tables", "collection", "collections",
            "record", "records", "row", "rows", "entity", "entities",
            
            # Cache & Performance
            "cache", "redis", "memcache", "session", "sessions", "temp",
            "temporary", "buffer", "queue", "jobs", "tasks",
            
            # Monitoring & Health
            "health", "healthcheck", "status", "ping", "alive", "ready",
            "metrics", "prometheus", "monitoring", "alerts",
            
            # Common File Extensions as Endpoints
            "json", "xml", "csv", "pdf", "txt", "html", "rss", "atom",
            
            # Version Control
            "git", "svn", "version", "versions", "release", "releases",
            "branch", "branches", "commit", "commits", "diff",
            
            # Common Subdirectories
            "public", "private", "internal", "external", "static",
            "assets", "resources", "lib", "libs", "vendor", "third-party"
        ]
    
    async def load_wordlists(self, custom_wordlist_path: str = None) -> List[str]:
        """Load wordlists from file and combine with default."""
        wordlist = set(self.default_wordlist)  # Start with default
        
        # Load custom wordlist if provided
        if custom_wordlist_path:
            try:
                custom_words = await self._load_wordlist_file(custom_wordlist_path)
                wordlist.update(custom_words)
                logger.info(f"Loaded {len(custom_words)} words from custom wordlist")
            except Exception as e:
                logger.warning(f"Failed to load custom wordlist: {str(e)}")
        
        # Convert back to list and sort
        final_wordlist = sorted(list(wordlist))
        logger.info(f"Total wordlist size: {len(final_wordlist)} endpoints")
        
        return final_wordlist
    
    async def _load_wordlist_file(self, file_path: str) -> List[str]:
        """Load wordlist from file."""
        words = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):  # Skip empty lines and comments
                        words.append(word)
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {file_path}")
            raise
        except Exception as e:
            logger.error(f"Error reading wordlist file: {str(e)}")
            raise
        
        return words
    
    def generate_variations(self, base_words: List[str]) -> List[str]:
        """Generate variations of base words."""
        variations = set(base_words)
        
        # Common prefixes and suffixes
        prefixes = ['api/', 'v1/', 'v2/', 'v3/', 'admin/', 'user/', 'public/', 'private/']
        suffixes = ['/', '.json', '.xml', '.html', '.php', '.asp', '.jsp']
        
        for word in base_words:
            # Add prefixes
            for prefix in prefixes:
                variations.add(f"{prefix}{word}")
            
            # Add suffixes
            for suffix in suffixes:
                variations.add(f"{word}{suffix}")
            
            # Add common variations
            variations.add(f"{word}s")  # Plural
            variations.add(f"{word}_list")  # List variant
            variations.add(f"{word}_detail")  # Detail variant
            variations.add(f"get_{word}")  # Get variant
            variations.add(f"create_{word}")  # Create variant
            variations.add(f"update_{word}")  # Update variant
            variations.add(f"delete_{word}")  # Delete variant
        
        return list(variations)
    
    def get_api_specific_wordlist(self, api_type: str = "rest") -> List[str]:
        """Get wordlist specific to API type."""
        base_list = self.default_wordlist.copy()
        
        if api_type.lower() == "graphql":
            graphql_words = [
                "graphql", "query", "mutation", "subscription", "schema",
                "introspection", "playground", "graphiql", "voyager"
            ]
            base_list.extend(graphql_words)
        
        elif api_type.lower() == "soap":
            soap_words = [
                "soap", "wsdl", "service", "services", "endpoint",
                "operation", "binding", "port", "envelope"
            ]
            base_list.extend(soap_words)
        
        elif api_type.lower() == "rpc":
            rpc_words = [
                "rpc", "jsonrpc", "xmlrpc", "method", "procedure",
                "call", "invoke", "execute", "remote"
            ]
            base_list.extend(rpc_words)
        
        return base_list 