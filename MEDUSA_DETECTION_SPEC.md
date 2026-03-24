# MEDUSA — Reweighted Framework Specification
# Focus: 80% Vulnerability Detection (ZAP/Nuclei replacement)
#        20% Network Penetration Testing
# Target Rating: 9.2 / 10
# Distribution: Stanford University Cybersecurity Research Division
#
# Kiro / Cursor: read this file completely before touching any code.
# This file redefines the priority and scope of the entire framework.
# Previous specs are still valid for architecture and GUI.
# This file overrides module priority and feature depth.

---

## Why This Reweight Hits 9.2

OWASP ZAP is the most widely deployed web security scanner in research and enterprise.
Its weaknesses are well documented:
  - Slow active scanning on modern JavaScript-heavy apps
  - Poor GraphQL and REST API coverage
  - No AI-assisted triage — generates enormous false positive volume
  - No template-based detection (Nuclei's core strength)
  - Reports are generic and require heavy manual editing
  - No built-in remediation guidance

Nuclei's strengths are its template ecosystem (9000+ community templates) and speed.
Its weaknesses:
  - No interactive proxy
  - No authenticated scanning without manual session config
  - No AI analysis of findings
  - Output is raw — no professional reporting

Medusa replaces both by combining:
  - Nuclei's template-based detection engine (speed + coverage)
  - ZAP's authenticated scanning and session management
  - AI triage that ZAP and Nuclei both lack entirely
  - Professional reporting neither tool produces

The 20% network module handles what Nessus Essentials covers for free —
port scanning, CVE correlation, service enumeration, and basic exploitation paths.

---

## MODULE PRIORITY MAP

### TIER 1 — Core Detection Engine (40% of total effort)
These modules define whether Medusa beats ZAP. Build these first, deepest.

  web/template_engine.py       Nuclei-compatible template runner
  web/crawler.py               Modern SPA-aware crawler (ZAP replacement)
  web/active_scanner.py        Active vulnerability probing (ZAP active scan replacement)
  web/passive_scanner.py       Passive analysis of proxied traffic (ZAP passive scan)
  web/authenticated_scanner.py Authenticated scanning with session management

### TIER 2 — Detection Coverage (25% of total effort)
What gets detected. Breadth and accuracy determine the rating.

  web/injectors.py             SQLi, XSS, SSRF, XXE, SSTI, SSTI
  web/api_scanner.py           REST, GraphQL, gRPC detection
  web/js_analyzer.py           Client-side vulnerability detection
  web/header_analyzer.py       Security header analysis
  web/waf_detector.py          WAF fingerprinting
  web/auth_tester.py           Authentication vulnerability detection
  web/orm_hunter.py            ORM escape hatch detection

### TIER 3 — AI Intelligence Layer (15% of total effort)
What separates Medusa from every existing tool.

  ai/triage.py                 False positive reduction
  ai/analyst.py                Per-finding deep analysis
  ai/chain_builder.py          Attack chain synthesis
  ai/report_writer.py          Professional narrative generation

### TIER 4 — Network Module (20% of total effort)
Solid but not the focus. Covers the basics a Stanford analyst needs.

  network/scanner.py           Nmap wrapper with CVE correlation
  network/cve_correlator.py    Real-time CVE + exploit lookup
  network/proto_testers.py     SMB, SNMP, LDAP, SSH, FTP
  network/cloud_enum.py        AWS, GCP, Azure asset discovery

### NOT IN SCOPE FOR 9.2 TARGET
Remove or deprioritise these — they dilute focus without improving the rating:

  redteam/c2.py                Remove from core — optional plugin only
  redteam/lateral.py           Remove from core — optional plugin only
  redteam/phishing_sim.py      Remove from core — optional plugin only
  redteam/active_dir.py        Keep as optional plugin — not core
  modules/mitm.py              Keep as optional plugin — not core

The red team modules are not gone. They become optional plugins the analyst
can enable. They do not run by default. The core product is a vulnerability scanner.

---

## TIER 1 — Template Engine (Nuclei Replacement)

### engine/modules/web/template_engine.py

This is the single most important module in Medusa.
Nuclei has 9000+ templates covering every CVE, misconfiguration,
exposed panel, and default credential scenario known.
Medusa must run these templates natively.

```python
"""
Kiro: implement this module completely.
It is the foundation of the 80% detection focus.
Everything else in the detection tier feeds into or extends this.
"""

class TemplateEngine:
    """
    Runs Nuclei-compatible YAML templates against targets.
    Medusa can consume the entire ProjectDiscovery template library directly.
    No template rewriting needed — use the existing ecosystem.
    """

    TEMPLATE_SOURCES = {
        "nuclei_community": {
            "repo": "https://github.com/projectdiscovery/nuclei-templates",
            "update_cmd": "nuclei -update-templates",
            "local_path": "~/.medusa/templates/nuclei/",
            "count": "9000+",
        },
        "custom_medusa": {
            "local_path": "engine/payloads/templates/custom/",
            "description": "Stanford-specific and engagement-specific templates",
        },
        "hackerone_disclosed": {
            "repo": "https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures",
            "description": "Templates from HackerOne disclosed reports",
        },
    }

    TEMPLATE_CATEGORIES = {
        # CVEs — the deepest coverage category
        "cves":             "CVE-specific detection templates (3000+ templates)",
        # Exposed panels
        "exposed-panels":   "Admin panels, login pages, management interfaces",
        # Default credentials
        "default-logins":   "Default username/password combinations",
        # Misconfigurations
        "misconfiguration": "Cloud, network, and application misconfigurations",
        # Exposures
        "exposures":        "Sensitive file exposure, backup files, source code",
        # Technologies
        "technologies":     "Technology fingerprinting",
        # Vulnerabilities
        "vulnerabilities":  "Application-specific vulnerability checks",
        # Network
        "network":          "Network protocol checks",
        # DNS
        "dns":              "DNS misconfiguration checks",
        # Fuzzing
        "fuzzing":          "Parameter fuzzing templates",
        # Workflows
        "workflows":        "Multi-step detection workflows",
    }

    async def setup(self) -> TemplateStats:
        """
        Initial setup — run once on first launch.

        1. Check if nuclei binary is installed: shutil.which("nuclei")
           If not: download via nuclei installer script or direct binary download.
           Store in ~/.medusa/bin/nuclei.
           Make executable.

        2. Update templates: nuclei -update-templates
           This downloads the full community template library (~9000 templates).
           Store in ~/.medusa/templates/nuclei/

        3. Index templates in SQLite:
           For each .yaml file: parse metadata (id, name, severity, tags, cve-id).
           Store in templates.db with full-text search index.
           This enables fast template filtering without re-scanning the filesystem.

        4. Return TemplateStats:
           total_templates: int
           by_severity: dict[str, int]
           by_category: dict[str, int]
           last_updated: datetime
        """

    async def run(
        self,
        target: str,
        session: Session,
        categories: list[str] | None = None,    # None = all categories
        severities: list[str] | None = None,    # None = all severities
        tags: list[str] | None = None,          # filter by tag
        cve_ids: list[str] | None = None,       # specific CVEs only
        concurrency: int = 50,                  # parallel template execution
        rate_limit: int = 150,                  # requests per second
        timeout: int = 10,                      # per-request timeout
    ) -> list[Finding]:
        """
        Core template execution engine.

        Build nuclei command:
        nuclei -target {target}
               -json-export {output_file}
               -rate-limit {rate_limit}
               -concurrency {concurrency}
               -timeout {timeout}
               -silent
               -no-color
               -stats
               [-tags {tags}]
               [-severity {severities}]
               [-templates {template_paths}]

        Stream nuclei stdout via asyncio.create_subprocess_exec.
        Parse each JSON line as it arrives — do not wait for completion.
        Each JSON line = one finding candidate.

        For each candidate:
          1. Parse: template_id, name, severity, matched_at, extracted_results,
                    curl_command, matcher_name, type.
          2. Create Finding object.
          3. Call ws_broadcaster.emit_finding() — appears in GUI immediately.
          4. Call Session.add_finding() — written to DB immediately.
          5. Queue for AI triage (do not block on AI — triage runs async).

        On completion:
          Run AI triage on all findings from this run.
          Update findings with triage results.
          Emit completion event to GUI.
        """

    async def run_workflow(
        self,
        target: str,
        workflow_name: str,
        session: Session,
    ) -> list[Finding]:
        """
        Nuclei workflows are multi-step detection sequences.
        Example: detect WordPress → run WordPress-specific templates.
        Example: detect login page → try default credentials.

        Run workflow YAML directly via nuclei -w {workflow_file}.
        Same parsing and streaming as run().
        """

    async def run_custom_template(
        self,
        target: str,
        template_path: str,
        session: Session,
    ) -> list[Finding]:
        """
        Run a single custom template.
        Used for:
          - Testing new templates before adding to library
          - Running Stanford-specific detection templates
          - Engagement-specific checks
        """

    async def update_templates(self) -> TemplateStats:
        """
        nuclei -update-templates
        Re-index after update.
        Emit progress to GUI during update.
        Return new template count.
        """

    def search_templates(
        self,
        query: str = "",
        category: str | None = None,
        severity: str | None = None,
        cve_id: str | None = None,
        tag: str | None = None,
    ) -> list[TemplateMetadata]:
        """
        Full-text search across template library.
        Used by GUI template browser.
        Returns matching templates with metadata.
        Fast — queries SQLite FTS index, not filesystem.
        """

    async def create_template(
        self,
        name: str,
        description: str,
        target_url_pattern: str,
        detection_logic: str,
        severity: str,
        tags: list[str],
    ) -> str:
        """
        AI-assisted template creation.
        Analyst describes what they want to detect.
        AI generates valid Nuclei YAML template syntax.
        Validate syntax before saving.
        Save to custom template directory.
        Return template path.

        This is the Stanford-specific power feature —
        analysts create custom templates for research targets
        without writing raw YAML manually.
        """
```

---

## TIER 1 — Authenticated Scanner (ZAP Replacement Core)

### engine/modules/web/authenticated_scanner.py

ZAP's biggest advantage over Nuclei is authenticated scanning.
This module is why Medusa replaces ZAP, not just adds to it.

```python
class AuthenticatedScanner:
    """
    Manages authentication state for scanning protected applications.
    Handles every authentication mechanism a modern web app uses.
    Once authenticated, all other scan modules run in the authenticated context.
    """

    AUTH_METHODS = {
        "form_login":    "HTML form with username/password fields",
        "basic_auth":    "HTTP Basic Authentication",
        "bearer_token":  "Authorization: Bearer header",
        "api_key":       "API key in header, query param, or cookie",
        "oauth2":        "OAuth 2.0 authorization code or client credentials",
        "saml":          "SAML SSO",
        "cookie":        "Pre-supplied session cookie",
        "script":        "Custom Python authentication script",
        "recorded":      "Recorded browser session (Playwright)",
    }

    async def authenticate(
        self,
        target: str,
        method: str,
        credentials: AuthCredentials,
        session: Session,
    ) -> AuthContext:
        """
        Authenticate against the target and return a context.
        AuthContext contains: cookies, headers, tokens — everything needed
        for subsequent authenticated requests.

        For form_login:
          1. Use Playwright to navigate to login URL.
          2. Auto-detect login form: find username/password fields by common names
             (username, email, user, login, password, pass, pwd).
          3. Fill and submit.
          4. Detect success: check for redirect away from login page,
             absence of login form, presence of user-specific content.
          5. Extract session cookies from Playwright context.
          6. Return AuthContext with cookies.

        For bearer_token:
          1. POST to token endpoint with credentials.
          2. Parse response for access_token.
          3. Return AuthContext with Authorization header.

        For oauth2:
          1. Navigate to authorization URL via Playwright.
          2. Complete authorization (auto-fill credentials on IdP login page).
          3. Intercept callback with authorization code.
          4. Exchange code for token.
          5. Return AuthContext with token.

        For recorded:
          1. Analyst records a Playwright session via GUI (Record Auth button).
          2. Save recording as Python script.
          3. Replay recording to get authenticated state.
          4. Extract cookies/tokens from final state.
        """

    async def verify_auth(self, auth_context: AuthContext, target: str) -> bool:
        """
        Verify authentication is still valid before each scan module runs.
        Send a request to a known-authenticated endpoint.
        If 401/403: re-authenticate automatically.
        If session expires during scan: re-authenticate and continue.
        Never let a scan fail silently due to session expiry.
        """

    async def scan_authenticated(
        self,
        target: str,
        auth_context: AuthContext,
        session: Session,
        modules: list[str],
    ) -> list[Finding]:
        """
        Run specified scan modules with authenticated context.
        Injects auth_context into every request made by every module.
        This is how ZAP works — one auth context, all modules use it.

        Modules receive auth_context as a parameter.
        They must apply it to every httpx request:
          headers.update(auth_context.headers)
          cookies.update(auth_context.cookies)
        """

    async def record_auth_session(self, target: str) -> str:
        """
        Opens a Playwright browser in headed mode.
        Analyst manually logs in.
        Playwright records all network requests made during login.
        Saves as an authentication script.
        Returns path to saved script.
        This is the ZAP "Record New Session" feature equivalent.
        """
```

---

## TIER 1 — Active Scanner (ZAP Active Scan Replacement)

### engine/modules/web/active_scanner.py

```python
class ActiveScanner:
    """
    Orchestrates all active scanning modules.
    Equivalent to ZAP's Active Scan with a scanner policy.
    Analyst selects a scan policy (speed vs depth) and this runs accordingly.
    """

    SCAN_POLICIES = {
        "quick": {
            "description": "Fast scan — headers, known CVEs, obvious misconfigs",
            "template_categories": ["technologies", "exposed-panels", "misconfiguration"],
            "nuclei_severity": ["critical", "high"],
            "active_checks": ["header_analyzer", "waf_detector"],
            "estimated_time": "2-5 minutes",
        },
        "standard": {
            "description": "Balanced scan — most detection categories, common vulns",
            "template_categories": ["cves", "vulnerabilities", "misconfiguration",
                                    "exposed-panels", "default-logins", "exposures"],
            "nuclei_severity": ["critical", "high", "medium"],
            "active_checks": ["header_analyzer", "waf_detector", "crawler",
                              "injectors", "auth_tester", "api_scanner"],
            "estimated_time": "15-45 minutes",
        },
        "deep": {
            "description": "Comprehensive scan — all templates, full fuzzing, API deep dive",
            "template_categories": ["all"],
            "nuclei_severity": ["critical", "high", "medium", "low"],
            "active_checks": ["all"],
            "estimated_time": "1-4 hours depending on application size",
        },
        "api": {
            "description": "API-focused — REST, GraphQL, authentication, authorization",
            "template_categories": ["vulnerabilities", "fuzzing"],
            "active_checks": ["api_scanner", "auth_tester", "injectors"],
            "estimated_time": "10-30 minutes",
        },
        "cve": {
            "description": "CVE-only — check for specific known vulnerabilities",
            "template_categories": ["cves"],
            "nuclei_severity": ["critical", "high"],
            "active_checks": [],
            "estimated_time": "5-15 minutes",
        },
    }

    async def run(
        self,
        target: str,
        policy: str,
        auth_context: AuthContext | None,
        session: Session,
    ) -> ScanResult:
        """
        Execute active scan according to policy.

        Execution order within a policy:
        1. header_analyzer (passive, fast — always first)
        2. waf_detector (sets WAF context for all subsequent modules)
        3. crawler (builds sitemap — feeds all subsequent modules)
        4. template_engine (Nuclei templates — widest coverage)
        5. injectors (SQLi, XSS, SSRF, XXE, SSTI)
        6. auth_tester (if credentials provided)
        7. api_scanner (if API endpoints detected)
        8. js_analyzer (client-side analysis)
        9. orm_hunter (after crawler identifies tech stack)

        Each module: emit progress to GUI, write findings immediately.
        After all modules: run AI triage, then AI chain builder.

        ScanResult:
          total_findings: int
          by_severity: dict
          by_category: dict
          scan_duration: float
          coverage_score: float   estimated % of attack surface covered
        """
```

---

## TIER 1 — Passive Scanner

### engine/modules/web/passive_scanner.py

```python
class PassiveScanner:
    """
    Analyses traffic without sending additional requests.
    ZAP's passive scanner is one of its most useful features —
    it analyses proxied traffic and flags issues without active probing.

    Medusa's passive scanner works in two modes:
    1. Intercept proxy mode — analysts browse the app, Medusa analyses traffic
    2. HAR file analysis — import a browser HAR file for offline analysis
    """

    PASSIVE_CHECKS = {
        "security_headers":     "Missing or misconfigured security headers",
        "cookie_flags":         "Missing Secure, HttpOnly, SameSite flags",
        "sensitive_data":       "Credentials, tokens, PII in responses",
        "information_leakage":  "Stack traces, server banners, debug info",
        "cors_policy":          "Overly permissive CORS configuration",
        "csp_analysis":         "CSP policy weaknesses",
        "mixed_content":        "HTTP resources loaded on HTTPS pages",
        "outdated_libraries":   "Vulnerable JS library versions",
        "jwt_analysis":         "JWT tokens — algorithm, expiry, claims",
        "api_key_exposure":     "API keys in responses or JS",
        "redirect_analysis":    "Open redirect candidates",
        "cache_control":        "Sensitive data cached by browser",
    }

    async def start_proxy(self, port: int = 8888) -> ProxyInfo:
        """
        Start an intercepting proxy using mitmproxy Python API.
        All traffic through the proxy is passively analysed.

        Proxy runs on localhost:{port}.
        GUI shows proxy status and a QR code / URL for mobile testing.
        Analyst configures browser to use localhost:{port} as HTTP proxy.
        Every request/response pair flows through passive checks.
        Findings appear in GUI in real time.

        Return ProxyInfo(host, port, ca_cert_path)
        so analyst can install the CA cert in their browser.
        """

    async def analyse_har(self, har_path: str, session: Session) -> list[Finding]:
        """
        Import and analyse a browser HAR (HTTP Archive) file.
        HAR files can be exported from Chrome DevTools, Firefox, Burp.
        This lets analysts capture complex authenticated flows manually
        and then run passive analysis without re-browsing.

        Parse HAR JSON. For each entry (request + response pair):
          Run all PASSIVE_CHECKS.
          Create findings for any issues detected.
        """

    async def analyse_request(
        self,
        request: HTTPRequest,
        response: HTTPResponse,
        session: Session,
    ) -> list[Finding]:
        """
        Analyse a single request/response pair.
        Called by proxy for each intercepted request.
        Must be fast — runs inline with proxy traffic.
        Target: < 10ms per request.
        """
```

---

## TIER 2 — API Scanner (ZAP Lacks This Depth)

### engine/modules/web/api_scanner.py

```python
class APIScanner:
    """
    Deep REST and GraphQL API vulnerability detection.
    This is where ZAP is weakest and Medusa must be strongest.
    Modern applications are APIs. ZAP was built for HTML apps.
    """

    async def scan_rest(
        self,
        target: str,
        spec: dict | None,      # OpenAPI/Swagger spec if available
        auth_context: AuthContext | None,
        session: Session,
    ) -> list[Finding]:
        """
        REST API scanning.

        Phase 1: Discovery
          Try common spec paths: /openapi.json, /swagger.json,
          /api-docs, /v1/docs, /api/swagger, /.well-known/api.
          If spec found: parse all endpoints.
          If no spec: extract from JS bundles via js_analyzer.

        Phase 2: Authentication testing
          Test every endpoint without auth — expect 401.
          If 200 without auth: BROKEN OBJECT LEVEL AUTHORIZATION.
          Test with expired token.
          Test with token from different user.

        Phase 3: Authorization testing (BOLA/IDOR)
          For each endpoint with resource ID parameter:
            Request resource owned by user A using user B credentials.
            If response contains user A data: BOLA confirmed.
          Requires two sets of credentials in auth config.

        Phase 4: Input validation
          For each parameter in each endpoint:
            Type confusion: string where int expected.
            Mass assignment: extra fields not in spec.
            Negative values, zero, max int, empty string.
            SQL injection via JSON body.
            XXE via XML content-type switch.

        Phase 5: Business logic
          Sequence manipulation: skip steps in multi-step flows.
          Price manipulation: negative quantities, zero prices.
          Rate limiting: rapid requests to sensitive endpoints.

        Phase 6: Information disclosure
          Verbose error messages revealing stack traces.
          Differences between 401 and 404 (user enumeration).
          Response size differences revealing data existence.
        """

    async def scan_graphql(
        self,
        endpoint: str,
        auth_context: AuthContext | None,
        session: Session,
    ) -> list[Finding]:
        """
        GraphQL-specific vulnerability detection.

        1. Introspection:
           Query: {__schema{types{name fields{name}}}}
           If enabled: schema exposed. Map all types and fields.
           Also try: {__type(name:"User"){fields{name}}}
           (Some implementations disable __schema but not __type)

        2. Field suggestion attack:
           Query invalid field names — GraphQL returns suggestions.
           Use suggestions to discover hidden fields.
           Example: {usr{passw...}} → "Did you mean: password?"

        3. Batch query abuse:
           [{query:"..."}, {query:"..."}, ...]
           Bypass rate limiting. Enumerate IDs in batch.

        4. Alias abuse:
           query { a:user(id:1){email} b:user(id:2){email} }
           Bypass per-field rate limiting.

        5. Deep recursion:
           {user{friends{friends{friends{friends{name}}}}}}
           Test query depth limiting. DoS if no limit.

        6. Fragment injection:
           fragment f on User { password }
           Test if sensitive fields exposed via fragments.

        7. Mutation testing:
           Test all mutations for authentication requirements.
           Test for SQL injection in mutation arguments.

        8. Subscription testing:
           Test WebSocket subscriptions for data leakage.
        """

    async def scan_grpc(
        self,
        endpoint: str,
        proto_files: list[str] | None,
        session: Session,
    ) -> list[Finding]:
        """
        gRPC service scanning using grpcurl.
        If proto files not provided: attempt reflection API.
        Test for: missing authentication, insecure TLS, injection in string fields.
        """
```

---

## TIER 2 — Comprehensive Injection Engine

### engine/modules/web/injectors.py — EXTENDED

The injectors must cover every injection class in OWASP Top 10 2021.
This is what determines detection breadth. Do not cut corners here.

```python
INJECTION_CLASSES = {
    # A03:2021 Injection
    "sqli": {
        "variants": [
            "error_based",      # MySQL/MSSQL/Postgres error messages
            "boolean_based",    # TRUE/FALSE response differences
            "time_based",       # Statistical timing (see PENTKIT_PRECISION.md)
            "union_based",      # UNION SELECT extraction
            "second_order",     # Stored and re-used in subsequent query
            "oob",              # Out-of-band via DNS/HTTP callback
            "nosql",            # MongoDB, CouchDB operator injection
            "ldap_injection",   # LDAP filter injection
            "xpath_injection",  # XPath query injection
        ],
        "detection_points": [
            "query_params", "post_body", "json_fields", "xml_nodes",
            "http_headers", "cookies", "path_segments", "graphql_args",
        ],
    },
    "xss": {
        "variants": [
            "reflected",        # Response reflects input immediately
            "stored",           # Input stored, reflected to other users
            "dom_based",        # Client-side JS processes attacker input
            "mutation",         # mXSS — browser mutation changes payload
            "blind",            # Executes in admin panel (use OOB callback)
        ],
        "contexts": [
            "html_body", "html_attribute", "js_string", "js_template_literal",
            "json_value", "href_attribute", "css_value", "html_comment",
            "svg_element", "event_handler",
        ],
    },
    "ssrf": {
        "targets": [
            "cloud_metadata",   # 169.254.169.254, 100.100.100.200 (Alibaba)
            "internal_services", # Redis, Elasticsearch, internal HTTP APIs
            "file_protocol",    # file:///etc/passwd
            "gopher_protocol",  # SSRF to Redis, Memcached via gopher://
            "dns_rebinding",    # DNS rebinding to bypass IP validation
        ],
    },
    "ssti": {
        "engines": {
            "jinja2":   "{{7*7}} → 49",
            "twig":     "{{7*7}} → 49",
            "freemarker": "${7*7} → 49",
            "velocity":  "#set($x=7*7)$x → 49",
            "smarty":   "{math equation='7*7'} → 49",
            "mako":     "${7*7} → 49",
            "erb":      "<%= 7*7 %> → 49",
            "pebble":   "{{7*7}} → 49",
        },
    },
    "xxe": {
        "variants": [
            "classic",          # External entity file read
            "blind_oob",        # OOB via HTTP/DNS callback
            "error_based",      # Error message contains file contents
            "xinclude",         # XInclude when DOCTYPE blocked
            "ssrf_via_xxe",     # SSRF using external entity URL
        ],
    },
    # A07:2021 Identification and Authentication Failures
    "auth": {
        "checks": [
            "brute_force_protection",  # Rate limiting on login
            "account_lockout",         # Lockout after N failures
            "credential_stuffing",     # Common password + enumerated users
            "password_reset_flaws",    # Token entropy, reuse, host header
            "session_fixation",        # Session ID unchanged after login
            "session_timeout",         # Excessive session lifetime
            "concurrent_sessions",     # Multiple simultaneous sessions allowed
            "jwt_vulnerabilities",     # alg:none, weak secret, kid injection
            "oauth_flaws",             # redirect_uri bypass, state missing
            "saml_flaws",             # Signature wrapping, XXE in SAML
        ],
    },
    # A01:2021 Broken Access Control
    "access_control": {
        "checks": [
            "idor",             # Insecure Direct Object Reference
            "bola",             # Broken Object Level Authorization (API)
            "bfla",             # Broken Function Level Authorization
            "path_traversal",   # ../../../etc/passwd
            "forced_browsing",  # Access /admin, /backup without auth
            "privilege_escalation", # Horizontal + vertical
            "cors_misconfiguration", # Wildcard, reflection, null origin
            "method_override",  # POST + X-HTTP-Method-Override: DELETE
        ],
    },
    # A05:2021 Security Misconfiguration
    "misconfiguration": {
        "checks": [
            "default_credentials",  # admin/admin, admin/password
            "directory_listing",    # Apache/Nginx directory index exposed
            "debug_endpoints",      # /debug, /console, /actuator/env
            "backup_files",         # .bak, .old, .orig, ~file
            "git_exposure",         # /.git/HEAD accessible
            "env_file_exposure",    # /.env accessible
            "cloud_metadata",       # IMDS endpoint accessible from web
            "error_disclosure",     # Stack traces in production
        ],
    },
    # A06:2021 Vulnerable and Outdated Components
    "components": {
        "checks": [
            "js_library_cve",   # Known CVEs in detected JS libraries
            "server_banner",    # Version disclosure in headers
            "framework_version", # Framework version → CVE lookup
        ],
    },
    # A09:2021 Security Logging and Monitoring Failures
    "logging": {
        "checks": [
            "log_injection",    # Newlines in log input
            "sensitive_logging", # Credentials/tokens in access logs
        ],
    },
}
```

---

## TIER 3 — AI Intelligence Layer

The AI layer is what separates Medusa from every free tool.
ZAP has no AI. Nuclei has no AI. Medusa has both.

### Priority order for AI calls:

```python
AI_TASK_PRIORITY = {
    # Highest value — runs on every finding
    1: "triage",           # False positive reduction — most important
    2: "severity_adjust",  # Re-score based on context
    3: "remediation",      # Developer-ready fix

    # High value — runs after module completes
    4: "chain_building",   # Attack path synthesis
    5: "template_creation", # Generate custom Nuclei templates from findings

    # Medium value — runs on demand
    6: "report_narrative",  # Executive summary generation
    7: "tech_analysis",     # Deep-dive on detected technology stack
}
```

### AI Triage — What Makes It Useful

```python
TRIAGE_SYSTEM_PROMPT = """
You are a senior application security engineer reviewing automated scan findings.
Your primary job is reducing false positives without missing real vulnerabilities.

For each finding you assess:

1. FALSE POSITIVE INDICATORS (flag these):
   - SQL error messages from legitimate input validation (not injection)
   - XSS reflection in error pages with strict CSP blocking execution
   - SSRF to localhost when application legitimately fetches local resources
   - "Missing header" findings when header is set by upstream proxy/CDN
   - Rate limiting findings on endpoints that legitimately allow rapid requests

2. TRUE POSITIVE INDICATORS (confirm these):
   - Evidence of actual data extraction in response
   - Confirmed code execution (OOB callback received)
   - Authentication bypass confirmed by accessing restricted resource
   - Error message reveals internal implementation details
   - Timing difference statistically confirmed by multiple trials

3. SEVERITY ADJUSTMENT:
   Network-only exploitable → downgrade one level (requires internal access)
   Authentication required → downgrade one level (reduces exploitability)
   No sensitive data accessible even if exploited → downgrade one level
   Credentials found in response → upgrade to CRITICAL regardless of template severity
   Direct path to admin access → upgrade to CRITICAL

Output must be valid JSON matching the FindingAssessment schema.
Be decisive. Do not say "this could be" — say "this is" or "this is not".
"""
```

---

## TIER 4 — Network Module (20% Focus)

Keep this solid but do not over-engineer. Cover what Nessus Essentials covers.

### What to build:

```python
NETWORK_MODULE_SCOPE = {
    "port_scanning": {
        "tool": "nmap (wrapped)",
        "depth": "SYN scan, top 1000 ports, OS detection, version detection",
        "output": "HostProfile with open ports, services, OS guess",
    },
    "cve_correlation": {
        "sources": ["NVD API v2", "ExploitDB"],
        "output": "CVE list per service with CVSS scores and exploit availability",
    },
    "service_enumeration": {
        "protocols": ["SMB", "SNMP", "LDAP", "FTP", "SSH", "RDP", "VNC"],
        "depth": "Version detection + known vulnerability checks",
        "output": "Service findings with specific CVEs",
    },
    "cloud_enumeration": {
        "providers": ["AWS S3", "Azure Blob", "GCP Storage", "Firebase"],
        "depth": "Bucket permutation + public access check",
        "output": "Exposed cloud storage findings",
    },
    "not_in_scope": [
        "MITM",             # Optional plugin only
        "AD attacks",       # Optional plugin only
        "Exploitation",     # Not the focus — identify, don't exploit
        "C2",               # Not in core at all
    ],
}
```

---

## GUI — Updated for Detection Focus

The GUI screens from MEDUSA_BLUEPRINT.md are correct but update these:

### New Engagement Wizard — Step 3 Module Selection

Replace the previous module layout with this priority-based layout:

```
DETECTION MODULES (primary — always shown first)
  Scan Policy: [Quick] [Standard] [Deep] [API] [CVE-Only]
  (selecting a policy auto-selects the right modules below)

  Core Detection:
    [x] Template Engine (Nuclei)    [x] Active Scanner
    [x] Passive Scanner / Proxy     [x] Crawler

  Web Vulnerabilities:
    [x] Injection (SQLi/XSS/SSRF)  [x] Authentication
    [x] API Scanner (REST/GraphQL)  [x] Access Control
    [x] JS Analyzer                 [x] Misconfigurations
    [x] Header Analyzer             [x] Component CVEs

  Authentication (optional — skip for unauthenticated scan):
    Auth Method: [None] [Form Login] [Bearer Token] [API Key] [OAuth2] [Recorded]
    (selecting any auth method shows the relevant credential fields)

NETWORK MODULES (secondary)
  [ ] Port Scanner + CVE Correlation
  [ ] Service Enumeration (SMB, SNMP, LDAP, SSH)
  [ ] Cloud Asset Discovery (S3, Azure, GCP)

OPTIONAL PLUGINS (not enabled by default)
  [ ] Red Team Modules (requires separate authorization confirmation)
```

### New Screen — Template Browser

Add this screen between Findings and Attack Chains in sidebar.

```
Template Browser
  Search bar: search 9000+ templates by name, CVE, tag, severity
  Filter panel: Category | Severity | Tags | Has Exploit | Recently Added
  Template list (AG Grid):
    ID | Name | Severity | Category | CVE | Tags | Last Updated
  Template detail panel (slides in from right):
    Full YAML syntax highlighted
    Description and references
    [Run Against Current Target] button
    [Clone and Edit] button — opens template editor
  Template editor:
    YAML editor with syntax highlighting and validation
    [Validate] button — checks syntax before saving
    [Test Run] button — runs against current target
    [Save to Custom Library] button
```

### Dashboard — Updated Metrics

```
Primary metrics (top row — 5 cards):
  Templates Run | Findings Today | False Positives Caught (AI) |
  Coverage Score % | Scan Time

Secondary metrics (second row):
  OWASP Top 10 coverage chart — which categories have findings
  Severity distribution donut
  Template category breakdown bar chart
  Recent scans table
```

---

## Rating Achievement Map

Here is exactly how Medusa reaches 9.2:

```
Template Engine (Nuclei-compatible, 9000+ templates): +2.1 points
  This is the single biggest rating driver.
  9000 templates covering every known CVE and misconfiguration.
  No tool built from scratch matches this coverage.
  Medusa runs them all natively.

Authenticated Scanning (ZAP parity):            +1.4 points
  ZAP's core strength. Now Medusa has it too.
  Form login, OAuth, Bearer, recorded sessions.
  Without this: Medusa misses 60% of real application findings.

AI Triage (false positive reduction):            +1.2 points
  ZAP: ~40% false positive rate on active scan.
  Nuclei: ~15% false positive rate (templates are precise).
  Medusa with AI triage: target < 8% false positive rate.
  This is the most professionally impactful feature.

API Scanner depth (GraphQL, REST, gRPC):         +0.9 points
  Neither ZAP nor Nuclei handles GraphQL well.
  Modern applications are APIs.
  Deep API coverage is a genuine gap in existing tools.

Passive Scanner + Proxy mode:                    +0.7 points
  ZAP's most used feature by security teams.
  Analysts browse an app, findings appear automatically.
  No other free tool matches ZAP here. Medusa now does.

Network module (Nessus Essentials scope):        +0.6 points
  Solid port scanning, CVE correlation, service enum.
  Not groundbreaking but necessary for a complete framework.

Professional Reporting (AI-generated):           +0.5 points
  Neither ZAP nor Nuclei produces usable reports without heavy editing.
  AI-generated executive summaries and technical narratives.
  Direct Jira export and SARIF for GitHub Security.

Adaptive Payload Engine + WAF Bypass:           +0.5 points
  Nuclei templates are static — same payload every time.
  Medusa mutates payloads based on WAF detection.
  Against hardened targets this is significant.

GUI (ease of use):                               +0.3 points
  ZAP's GUI is dated and confusing.
  Nuclei has no GUI.
  Medusa's modern Electron GUI removes friction.

TOTAL RATING DELTA:                              +8.2 from baseline
ACHIEVABLE RATING:                               9.2 / 10
```

---

## Build Order — Revised for Detection Focus

```
PHASE 1: Foundation (same as before)
  All core/ modules. Scope guard first. AI engine second.

PHASE 2: Template Engine (HIGHEST PRIORITY)
  engine/modules/web/template_engine.py
  Install nuclei binary in setup.
  Download community templates.
  Index in SQLite.
  Wire to FastAPI: POST /api/scans/templates/run
  Wire to GUI: Template Browser screen.
  Test: run against DVWA via GUI, verify findings appear.

PHASE 3: Crawler + Passive Scanner
  engine/modules/web/crawler.py
  engine/modules/web/passive_scanner.py (with mitmproxy proxy mode)
  Wire proxy to GUI: show proxy status, install CA cert instructions.

PHASE 4: Authenticated Scanner
  engine/modules/web/authenticated_scanner.py
  Wire to New Engagement wizard: auth method selector.
  Test: authenticated scan against DVWA (login required sections).

PHASE 5: Active Scanner Orchestrator
  engine/modules/web/active_scanner.py
  Wire scan policies to GUI: Quick/Standard/Deep/API/CVE toggles.
  Wire all detection modules into orchestrator.

PHASE 6: Detection Modules (in parallel — all feed into active scanner)
  web/injectors.py        (full injection class coverage from spec above)
  web/api_scanner.py      (REST + GraphQL + gRPC)
  web/auth_tester.py      (full auth check list)
  web/js_analyzer.py
  web/header_analyzer.py
  web/waf_detector.py + waf_bypass.py
  web/orm_hunter.py

PHASE 7: AI Layer
  ai/triage.py            (run after every module, reduces false positives)
  ai/analyst.py           (per-finding deep analysis)
  ai/chain_builder.py     (attack synthesis)
  ai/report_writer.py     (narrative generation)
  Wire to GUI: AI analysis tab in Finding Detail.

PHASE 8: Network Module
  network/scanner.py
  network/cve_correlator.py
  network/proto_testers.py
  network/cloud_enum.py

PHASE 9: Output Layer
  output/csv_exporter.py  (full column set from csv spec)
  output/report_engine.py
  output/sarif_export.py
  output/jira_export.py
  Blue team: sigma_generator, ioc_extractor, hardening_advisor

PHASE 10: GUI completion + packaging
  All pages fully implemented.
  Template Browser screen.
  electron-builder package.
  pyinstaller bundle.
  Smoke test on clean machine.
```

---

## Final Note to Kiro / Cursor

The 80/20 split is the strategic decision that makes 9.2 achievable.

Trying to be the best web scanner AND the best network scanner AND
the best red team framework AND the best reporting tool simultaneously
produces a mediocre tool that does everything at 6/10.

Medusa is the best web vulnerability scanner available to Stanford analysts.
Full stop. That is the goal.
The network module is solid and professional.
The red team plugins exist for analysts who need them.
But the core identity is: OWASP ZAP replacement with Nuclei template coverage
and AI intelligence that neither tool has.

Build that. Reach 9.2. Ship it.
```
