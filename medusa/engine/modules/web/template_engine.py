"""
Nuclei-compatible template engine — TIER 1 core detection module.
Runs 9000+ community templates. Replaces Nuclei as standalone tool.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from medusa.engine.core.session import Session
from medusa.engine.core.ws_broadcaster import WSBroadcaster

__all__ = ["TemplateEngine", "TemplateStats", "TemplateMetadata"]

logger = logging.getLogger(__name__)

MEDUSA_DIR = Path.home() / ".medusa"
NUCLEI_BIN_DIR = MEDUSA_DIR / "bin"
TEMPLATE_DIR = MEDUSA_DIR / "templates" / "nuclei"
CUSTOM_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "payloads" / "templates" / "custom"
TEMPLATE_DB = MEDUSA_DIR / "templates.db"

_NUCLEI_RELEASES = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"


@dataclass
class TemplateStats:
    total_templates: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TemplateMetadata:
    id: str
    name: str
    severity: str
    category: str
    tags: list[str]
    cve_ids: list[str]
    path: str
    description: str = ""
    author: str = ""


@dataclass
class NucleiResult:
    template_id: str
    name: str
    severity: str
    matched_at: str
    extracted_results: list[str]
    curl_command: str
    matcher_name: str
    type: str
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


def _nuclei_bin() -> Path:
    """Return path to the nuclei binary."""
    system = platform.system().lower()
    name = "nuclei.exe" if system == "windows" else "nuclei"
    return NUCLEI_BIN_DIR / name


def _find_nuclei() -> str | None:
    """Find nuclei binary — check PATH first, then ~/.medusa/bin."""
    found = shutil.which("nuclei")
    if found:
        return found
    local = _nuclei_bin()
    if local.exists():
        return str(local)
    return None


async def _download_nuclei() -> Path:
    """Download nuclei binary from GitHub releases."""
    import urllib.request, zipfile, tarfile, io

    system = platform.system().lower()
    arch = platform.machine().lower()
    if arch in ("x86_64", "amd64"):
        arch = "amd64"
    elif arch in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = "amd64"

    if system == "windows":
        asset_name = f"nuclei_{arch}.zip"
    elif system == "darwin":
        asset_name = f"nuclei_macOS_{arch}.zip"
    else:
        asset_name = f"nuclei_linux_{arch}.zip"

    logger.info("Fetching nuclei release info …")
    try:
        with urllib.request.urlopen(_NUCLEI_RELEASES, timeout=15) as resp:
            release = json.loads(resp.read())
        assets = release.get("assets", [])
        url = next(
            (a["browser_download_url"] for a in assets if asset_name in a["name"]),
            None,
        )
        if not url:
            # fallback: infer latest version tag
            tag = release.get("tag_name", "v3.2.0")
            ver = tag.lstrip("v")
            url = (
                f"https://github.com/projectdiscovery/nuclei/releases/download/{tag}/"
                f"nuclei_{ver}_{system}_{arch}.zip"
            )

        NUCLEI_BIN_DIR.mkdir(parents=True, exist_ok=True)
        bin_path = _nuclei_bin()

        logger.info("Downloading nuclei from %s …", url)
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()

        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if "nuclei" in name.lower() and not name.endswith("/"):
                        with zf.open(name) as src, open(bin_path, "wb") as dst:
                            dst.write(src.read())
                        break
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for member in tf.getmembers():
                    if "nuclei" in member.name.lower() and member.isfile():
                        src = tf.extractfile(member)
                        if src:
                            with open(bin_path, "wb") as dst:
                                dst.write(src.read())
                        break

        # make executable
        st = os.stat(bin_path)
        os.chmod(bin_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        logger.info("nuclei installed at %s", bin_path)
        return bin_path
    except Exception as exc:
        logger.error("Failed to download nuclei: %s", exc)
        raise


def _init_template_db() -> sqlite3.Connection:
    """Initialize SQLite template index with FTS5."""
    MEDUSA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(TEMPLATE_DB))
    con.execute("""
        CREATE TABLE IF NOT EXISTS templates (
            id TEXT PRIMARY KEY,
            name TEXT,
            severity TEXT,
            category TEXT,
            tags TEXT,
            cve_ids TEXT,
            path TEXT,
            description TEXT,
            author TEXT
        )
    """)
    con.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS templates_fts
        USING fts5(id, name, description, tags, cve_ids, content=templates)
    """)
    con.commit()
    return con


def _parse_template_yaml(path: Path) -> TemplateMetadata | None:
    """Parse a single Nuclei YAML template for metadata without full YAML parser."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        meta: dict[str, Any] = {"id": "", "name": "", "severity": "info",
                                  "tags": [], "cve_ids": [], "description": "", "author": ""}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("id:") and not meta["id"]:
                meta["id"] = stripped[3:].strip().strip("'\"")
            elif stripped.startswith("name:") and not meta["name"]:
                meta["name"] = stripped[5:].strip().strip("'\"")
            elif stripped.startswith("severity:"):
                meta["severity"] = stripped[9:].strip().strip("'\"").lower()
            elif stripped.startswith("tags:"):
                raw = stripped[5:].strip()
                meta["tags"] = [t.strip() for t in raw.split(",")]
            elif stripped.startswith("description:") and not meta["description"]:
                meta["description"] = stripped[12:].strip().strip("'\"")
            elif stripped.startswith("author:") and not meta["author"]:
                meta["author"] = stripped[7:].strip().strip("'\"")

        # extract CVE IDs from id and tags
        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
        cves = cve_pattern.findall(meta["id"] + " " + " ".join(meta["tags"]))
        meta["cve_ids"] = list({c.upper() for c in cves})

        # category = parent directory name
        category = path.parent.name

        if not meta["id"]:
            return None
        return TemplateMetadata(
            id=meta["id"],
            name=meta["name"] or meta["id"],
            severity=meta["severity"],
            category=category,
            tags=meta["tags"],
            cve_ids=meta["cve_ids"],
            path=str(path),
            description=meta["description"],
            author=meta["author"],
        )
    except Exception as exc:
        logger.debug("Parse template %s failed: %s", path, exc)
        return None


def _index_templates(con: sqlite3.Connection, base_dir: Path) -> TemplateStats:
    """Walk template directory and index all YAML files into SQLite."""
    stats = TemplateStats()
    con.execute("DELETE FROM templates")
    con.execute("DELETE FROM templates_fts")

    rows = []
    for yaml_path in base_dir.rglob("*.yaml"):
        tm = _parse_template_yaml(yaml_path)
        if tm is None:
            continue
        rows.append((
            tm.id, tm.name, tm.severity, tm.category,
            ",".join(tm.tags), ",".join(tm.cve_ids),
            tm.path, tm.description, tm.author,
        ))
        stats.total_templates += 1
        stats.by_severity[tm.severity] = stats.by_severity.get(tm.severity, 0) + 1
        stats.by_category[tm.category] = stats.by_category.get(tm.category, 0) + 1

    con.executemany(
        "INSERT OR REPLACE INTO templates VALUES (?,?,?,?,?,?,?,?,?)", rows
    )
    con.executemany(
        "INSERT INTO templates_fts(id, name, description, tags, cve_ids) "
        "VALUES (?,?,?,?,?)",
        [(r[0], r[1], r[7], r[4], r[5]) for r in rows],
    )
    con.commit()
    logger.info("Indexed %d templates", stats.total_templates)
    return stats


def _parse_nuclei_json_line(line: str) -> NucleiResult | None:
    """Parse a single JSON line from nuclei -json output."""
    try:
        data = json.loads(line.strip())
        info = data.get("info", {})
        return NucleiResult(
            template_id=data.get("template-id", ""),
            name=info.get("name", data.get("template-id", "")),
            severity=info.get("severity", "info"),
            matched_at=data.get("matched-at", ""),
            extracted_results=data.get("extracted-results", []),
            curl_command=data.get("curl-command", ""),
            matcher_name=data.get("matcher-name", ""),
            type=data.get("type", "http"),
            tags=info.get("tags", "").split(",") if isinstance(info.get("tags"), str) else [],
            cve_ids=[c.upper() for c in (info.get("classification", {}) or {}).get("cve-id", [])],
        )
    except Exception:
        return None


class TemplateEngine:
    """
    Nuclei-compatible template runner.
    Runs community templates and custom Medusa templates against targets.
    """

    TEMPLATE_SOURCES = {
        "nuclei_community": {
            "repo": "https://github.com/projectdiscovery/nuclei-templates",
            "update_cmd": "nuclei -update-templates",
            "local_path": str(TEMPLATE_DIR),
            "count": "9000+",
        },
        "custom_medusa": {
            "local_path": str(CUSTOM_TEMPLATE_DIR),
            "description": "Custom and engagement-specific templates",
        },
    }

    TEMPLATE_CATEGORIES = {
        "cves":             "CVE-specific detection templates (3000+ templates)",
        "exposed-panels":   "Admin panels, login pages, management interfaces",
        "default-logins":   "Default username/password combinations",
        "misconfiguration": "Cloud, network, and application misconfigurations",
        "exposures":        "Sensitive file exposure, backup files, source code",
        "technologies":     "Technology fingerprinting",
        "vulnerabilities":  "Application-specific vulnerability checks",
        "network":          "Network protocol checks",
        "dns":              "DNS misconfiguration checks",
        "fuzzing":          "Parameter fuzzing templates",
        "workflows":        "Multi-step detection workflows",
    }

    def __init__(self, broadcaster: WSBroadcaster | None = None) -> None:
        self.broadcaster = broadcaster or WSBroadcaster()
        self._db: sqlite3.Connection | None = None

    def _db_conn(self) -> sqlite3.Connection:
        if self._db is None:
            self._db = _init_template_db()
        return self._db

    async def setup(self) -> TemplateStats:
        """
        Initial setup — run once on first launch.
        1. Check / install nuclei binary.
        2. Update templates.
        3. Index in SQLite.
        4. Return TemplateStats.
        """
        nuclei = _find_nuclei()
        if not nuclei:
            logger.info("nuclei not found — downloading …")
            try:
                await _download_nuclei()
            except Exception as exc:
                logger.error("Nuclei download failed: %s. Template engine will be limited.", exc)

        return await self.update_templates()

    async def update_templates(self) -> TemplateStats:
        """nuclei -update-templates, then re-index."""
        nuclei = _find_nuclei()
        if nuclei:
            TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
            try:
                proc = await asyncio.create_subprocess_exec(
                    nuclei,
                    "-update-templates",
                    "-update-template-dir", str(TEMPLATE_DIR),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                out, _ = await proc.communicate()
                logger.info("Template update: %s", (out or b"").decode(errors="ignore")[:500])
            except Exception as exc:
                logger.warning("Template update failed: %s", exc)

        if TEMPLATE_DIR.exists():
            con = self._db_conn()
            stats = _index_templates(con, TEMPLATE_DIR)
            if CUSTOM_TEMPLATE_DIR.exists():
                custom_stats = _index_templates(con, CUSTOM_TEMPLATE_DIR)
                stats.total_templates += custom_stats.total_templates
            return stats
        return TemplateStats()

    def search_templates(
        self,
        query: str = "",
        category: str | None = None,
        severity: str | None = None,
        cve_id: str | None = None,
        tag: str | None = None,
    ) -> list[TemplateMetadata]:
        """Full-text search across template library via SQLite FTS."""
        con = self._db_conn()
        clauses: list[str] = []
        params: list[Any] = []

        base_query = "SELECT t.id, t.name, t.severity, t.category, t.tags, t.cve_ids, t.path, t.description, t.author FROM templates t"

        if query:
            base_query = (
                "SELECT t.id, t.name, t.severity, t.category, t.tags, t.cve_ids, t.path, t.description, t.author "
                "FROM templates t JOIN templates_fts fts ON t.id = fts.id "
                "WHERE templates_fts MATCH ?"
            )
            params.append(query)
        else:
            base_query += " WHERE 1=1"

        if category:
            clauses.append("t.category = ?")
            params.append(category)
        if severity:
            clauses.append("t.severity = ?")
            params.append(severity.lower())
        if cve_id:
            clauses.append("t.cve_ids LIKE ?")
            params.append(f"%{cve_id.upper()}%")
        if tag:
            clauses.append("t.tags LIKE ?")
            params.append(f"%{tag}%")

        if clauses and "WHERE" in base_query:
            base_query += " AND " + " AND ".join(clauses)
        elif clauses:
            base_query += " WHERE " + " AND ".join(clauses)

        base_query += " LIMIT 500"

        try:
            rows = con.execute(base_query, params).fetchall()
            return [
                TemplateMetadata(
                    id=r[0], name=r[1], severity=r[2], category=r[3],
                    tags=r[4].split(",") if r[4] else [],
                    cve_ids=r[5].split(",") if r[5] else [],
                    path=r[6], description=r[7] or "", author=r[8] or "",
                )
                for r in rows
            ]
        except Exception as exc:
            logger.warning("Template search error: %s", exc)
            return []

    async def run(
        self,
        target: str,
        session: Session,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        tags: list[str] | None = None,
        cve_ids: list[str] | None = None,
        concurrency: int = 50,
        rate_limit: int = 150,
        timeout: int = 10,
        auth_headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Core template execution engine.
        Streams nuclei output, parses each JSON line, writes findings immediately.
        """
        nuclei = _find_nuclei()
        if not nuclei:
            logger.warning("nuclei binary not found — skipping template scan")
            await self.broadcaster.log(session.id, "WARNING",
                                       "nuclei not found — install it or run setup()", "template_engine")
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_file = tf.name

        cmd = [
            nuclei,
            "-target", target,
            "-json-export", output_file,
            "-rate-limit", str(rate_limit),
            "-concurrency", str(concurrency),
            "-timeout", str(timeout),
            "-silent",
            "-no-color",
            "-stats",
        ]

        if severities:
            cmd += ["-severity", ",".join(severities)]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if cve_ids:
            tmpl_paths = []
            for cve in cve_ids:
                cve_dir = TEMPLATE_DIR / "cves"
                if cve_dir.exists():
                    for p in cve_dir.rglob(f"*{cve.lower()}*"):
                        tmpl_paths.append(str(p))
            if tmpl_paths:
                cmd += ["-templates", ",".join(tmpl_paths)]
        elif categories:
            tmpl_paths = []
            for cat in categories:
                cat_dir = TEMPLATE_DIR / cat
                if cat_dir.exists():
                    tmpl_paths.append(str(cat_dir))
            if tmpl_paths:
                cmd += ["-templates", ",".join(tmpl_paths)]
        elif TEMPLATE_DIR.exists():
            cmd += ["-templates", str(TEMPLATE_DIR)]

        # Inject auth headers via env or header flag
        if auth_headers:
            for k, v in auth_headers.items():
                cmd += ["-H", f"{k}: {v}"]

        env = os.environ.copy()

        await self.broadcaster.log(session.id, "INFO",
                                   f"[template_engine] Starting Nuclei scan on {target}", "template_engine")
        await self.broadcaster.emit_progress(session.id, "template_engine", 0, "running")

        findings: list[dict[str, Any]] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # Stream stderr for progress logs
            async def _read_stderr() -> None:
                if proc.stderr:
                    async for line in proc.stderr:
                        text = line.decode(errors="ignore").strip()
                        if text:
                            logger.debug("[nuclei stderr] %s", text)
                            await self.broadcaster.log(session.id, "DEBUG", text, "template_engine")

            asyncio.create_task(_read_stderr())

            if proc.stdout:
                async for raw_line in proc.stdout:
                    line = raw_line.decode(errors="ignore").strip()
                    if not line:
                        continue
                    result = _parse_nuclei_json_line(line)
                    if result:
                        sev = result.severity.lower()
                        if sev not in ("critical", "high", "medium", "low", "info"):
                            sev = "info"
                        finding = session.add_finding(
                            module="web.template_engine",
                            target=result.matched_at or target,
                            title=result.name,
                            description=(
                                f"Template: {result.template_id}\n"
                                f"Matched at: {result.matched_at}\n"
                                f"Matcher: {result.matcher_name}\n"
                                f"Extracted: {', '.join(result.extracted_results)}"
                            ),
                            severity=sev,  # type: ignore
                            payload=result.curl_command[:4096] if result.curl_command else None,
                            cve_ids=result.cve_ids,
                            tags=["nuclei", result.template_id] + result.tags,
                            details={
                                "template_id": result.template_id,
                                "extracted_results": result.extracted_results,
                                "curl_command": result.curl_command[:2048] if result.curl_command else "",
                                "matcher_name": result.matcher_name,
                                "type": result.type,
                            },
                        )
                        await self.broadcaster.emit_finding(session.id, finding)
                        findings.append({
                            "template_id": result.template_id,
                            "name": result.name,
                            "severity": sev,
                            "matched_at": result.matched_at,
                        })
                        await self.broadcaster.log(
                            session.id, "SUCCESS" if sev in ("critical", "high") else "INFO",
                            f"[{sev.upper()}] {result.name} @ {result.matched_at}", "template_engine",
                        )

            await proc.wait()
        except FileNotFoundError:
            logger.error("nuclei binary not found at expected path")
            await self.broadcaster.log(session.id, "ERROR", "nuclei binary not found", "template_engine")
        except Exception as exc:
            logger.error("Template engine error: %s", exc)
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass

        await self.broadcaster.emit_progress(session.id, "template_engine", 100, "done")
        await self.broadcaster.log(
            session.id, "SUCCESS",
            f"[template_engine] Completed. {len(findings)} findings.", "template_engine",
        )
        return findings

    async def run_workflow(self, target: str, workflow_name: str, session: Session) -> list[dict[str, Any]]:
        """Run a named Nuclei workflow YAML."""
        nuclei = _find_nuclei()
        if not nuclei:
            return []
        workflow_path = TEMPLATE_DIR / "workflows" / f"{workflow_name}.yaml"
        if not workflow_path.exists():
            logger.warning("Workflow not found: %s", workflow_path)
            return []
        return await self._run_with_args(
            target, session, extra_args=["-w", str(workflow_path)]
        )

    async def run_custom_template(self, target: str, template_path: str, session: Session) -> list[dict[str, Any]]:
        """Run a single custom template."""
        nuclei = _find_nuclei()
        if not nuclei:
            return []
        if not Path(template_path).exists():
            logger.warning("Template not found: %s", template_path)
            return []
        return await self._run_with_args(
            target, session, extra_args=["-templates", template_path]
        )

    async def _run_with_args(
        self, target: str, session: Session, extra_args: list[str]
    ) -> list[dict[str, Any]]:
        """Internal helper to run nuclei with extra args."""
        nuclei = _find_nuclei()
        if not nuclei:
            return []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_file = tf.name
        cmd = [nuclei, "-target", target, "-json-export", output_file, "-silent", "-no-color"] + extra_args
        findings = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            # read output file
            out_path = Path(output_file)
            if out_path.exists():
                for line in out_path.read_text(errors="ignore").splitlines():
                    result = _parse_nuclei_json_line(line)
                    if result:
                        sev = result.severity.lower()
                        if sev not in ("critical", "high", "medium", "low", "info"):
                            sev = "info"
                        finding = session.add_finding(
                            module="web.template_engine",
                            target=result.matched_at or target,
                            title=result.name,
                            description=f"Template: {result.template_id}",
                            severity=sev,  # type: ignore
                            cve_ids=result.cve_ids,
                            tags=["nuclei", result.template_id],
                        )
                        await self.broadcaster.emit_finding(session.id, finding)
                        findings.append({"template_id": result.template_id, "severity": sev})
        except Exception as exc:
            logger.error("Template run error: %s", exc)
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass
        return findings

    async def create_template(
        self,
        name: str,
        description: str,
        target_url_pattern: str,
        detection_logic: str,
        severity: str,
        tags: list[str],
        ai_engine: Any = None,
    ) -> str:
        """AI-assisted custom Nuclei template creation."""
        CUSTOM_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)

        if ai_engine:
            system = (
                "You are a Nuclei template expert. Generate valid Nuclei YAML template syntax. "
                "Output ONLY the raw YAML, no markdown, no explanation."
            )
            user = (
                f"Create a Nuclei template with:\n"
                f"Name: {name}\n"
                f"Description: {description}\n"
                f"Target URL pattern: {target_url_pattern}\n"
                f"Detection logic: {detection_logic}\n"
                f"Severity: {severity}\n"
                f"Tags: {', '.join(tags)}\n\n"
                "Output a complete, valid Nuclei YAML template."
            )
            yaml_content = await ai_engine.complete(system, user)
        else:
            # Fallback template
            safe_id = name.lower().replace(" ", "-")
            yaml_content = f"""id: {safe_id}
info:
  name: {name}
  author: medusa
  severity: {severity}
  description: {description}
  tags: {",".join(tags)}

http:
  - method: GET
    path:
      - "{target_url_pattern}"
    matchers:
      - type: word
        words:
          - "{detection_logic}"
"""

        # Validate — ensure it at least has an id field
        if "id:" not in yaml_content:
            raise ValueError("AI-generated template is missing required 'id' field")

        safe_id = name.lower().replace(" ", "-").replace("/", "_")
        tmpl_path = CUSTOM_TEMPLATE_DIR / f"{safe_id}.yaml"
        tmpl_path.write_text(yaml_content, encoding="utf-8")
        logger.info("Custom template saved: %s", tmpl_path)
        return str(tmpl_path)
