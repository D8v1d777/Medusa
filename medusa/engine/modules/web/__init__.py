"""Web security modules — Medusa Framework."""
from medusa.engine.modules.web.active_scanner import ActiveScanner, ScanResult
from medusa.engine.modules.web.api_scanner import APIScanner
from medusa.engine.modules.web.authenticated_scanner import AuthenticatedScanner, AuthContext, AuthCredentials
from medusa.engine.modules.web.crawler import Crawler, SiteMap, Form, Endpoint
from medusa.engine.modules.web.header_analyzer import HeaderAnalyzer
from medusa.engine.modules.web.injectors import Injectors
from medusa.engine.modules.web.js_analyzer import JSAnalyzer
from medusa.engine.modules.web.orm_hunter import ORMHunter
from medusa.engine.modules.web.passive_scanner import PassiveScanner, ProxyInfo
from medusa.engine.modules.web.template_engine import TemplateEngine, TemplateMetadata
from medusa.engine.modules.web.waf_detector import WAFDetector, WAFProfile

__all__ = [
    "ActiveScanner", "ScanResult", "APIScanner", "AuthenticatedScanner", "AuthContext", "AuthCredentials",
    "Crawler", "SiteMap", "Form", "Endpoint", "HeaderAnalyzer", "Injectors", "JSAnalyzer", "ORMHunter",
    "PassiveScanner", "ProxyInfo", "TemplateEngine", "TemplateMetadata", "WAFDetector", "WAFProfile"
]
