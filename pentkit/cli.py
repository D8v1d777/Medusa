import click
import os
import sys
import asyncio
from typing import Optional
from pentkit.core import get_config, Session, ScopeGuard, RateLimiter, AIEngine, setup_logger
from pentkit.core.dependency_check import run_checks_and_exit_if_failed

@click.group()
def main():
    """Authorized Pentesting Framework — pentkit"""
    run_checks_and_exit_if_failed()
    pass

@main.group()
def scan():
    """Scan modules (web, network, redteam)"""
    pass

@scan.command()
@click.option('--target', required=True, help='Target URL')
@click.option('--config', default="config.yaml", help='Path to engagement config YAML')
@click.option('--resume', help='Resume session with ID')
def web(target, config, resume):
    """Run web module against target URL"""
    from pentkit.modules.web import WebModule
    
    cfg = get_config(config)
    if not cfg.engagement.authorized:
        click.echo("Error: Engagement not authorized in config. Exiting.")
        sys.exit(1)
        
    session = Session(cfg, session_id=resume)
    setup_logger(cfg, session_id=session.id)
    
    guard = ScopeGuard(ips=cfg.scope.ips, domains=cfg.scope.domains, cidrs=cfg.scope.cidrs)
    limiter = RateLimiter(cfg)
    ai = AIEngine(cfg.ai)
    
    module = WebModule(guard, limiter, ai)
    
    click.echo(f"Starting web scan on {target} (Session: {session.id})")
    asyncio.run(module.run(target, session))
    
    # Finalize CSV export with summary row
    asyncio.run(session.csv_exporter.write_summary())
    
    click.echo(f"Web scan complete. Findings added to session {session.id}")
    click.echo(f"Web findings exported to: {session.csv_exporter.csv_path}")
    
    # Print summary stats
    from pentkit.core.models import FindingModel
    findings = session.db_session.query(FindingModel).filter(FindingModel.module.like("web.%")).all()
    critical = sum(1 for f in findings if f.severity.lower() == "critical")
    high = sum(1 for f in findings if f.severity.lower() == "high")
    verified = sum(1 for f in findings if f.details.get("verified") is True)
    click.echo(f"Total rows: {len(findings)} | Critical: {critical} | High: {high} | Verified: {verified}")

@scan.command()
@click.option('--target', required=True, help='Target IP/CIDR')
@click.option('--evade', type=click.Choice(['fragment', 'decoy', 'ttl', 'timing']), 
              help='Evasion techniques')
@click.option('--config', help='Path to engagement config YAML')
@click.option('--resume', help='Resume session with ID')
def network(target, evade, config, resume):
    """Run network module against target IP/CIDR"""
    from pentkit.modules.network import run as run_network
    cfg = get_config(config)
    if not cfg.engagement.authorized:
        click.echo("Error: Engagement not authorized in config. Exiting.")
        sys.exit(1)
    session = Session(cfg, session_id=resume)
    setup_logger(cfg, session_id=session.id)
    click.echo(f"Starting network scan on {target} with {evade or 'no'} evasion (Session: {session.id})")
    asyncio.run(run_network(target, session, evasion=evade))
    click.echo(f"Network scan complete. Findings added to session {session.id}")

@scan.command()
@click.option('--target', multiple=True, help='Target URL or IP (can be multiple)')
@click.option('--config', help='Path to engagement config YAML')
def all(target, config):
    """Run web + network modules sequentially"""
    if config:
        init_config(config)
    session = Session()
    click.echo(f"Starting full scan on {target} (Session: {session.id})")
    # Placeholder for full module execution
    pass

@scan.command()
@click.option('--confirm-auth', is_flag=True, help='Explicitly confirm authorization')
@click.option('--config', help='Path to engagement config YAML')
def redteam(confirm_auth, config):
    """Run red team module (requires --confirm-auth)"""
    from pentkit.modules.redteam import run as run_redteam
    if not confirm_auth:
        click.echo("Red team module requires explicit confirmation with --confirm-auth")
        sys.exit(1)
    if config:
        init_config(config)
    
    cfg = get_config(config)
    if not cfg.engagement.authorized:
        click.echo("Error: Engagement not authorized in config. Exiting.")
        sys.exit(1)
    
    click.echo(f"Engagement: {cfg.engagement.name if cfg else 'N/A'}")
    click.echo(f"Operator: {cfg.engagement.operator if cfg else 'N/A'}")
    click.echo(f"Scope: {cfg.scope.model_dump() if cfg else 'N/A'}")
    
    confirmation = click.prompt("Type the engagement name to confirm")
    if cfg and confirmation != cfg.engagement.name:
        click.echo("Confirmation failed. Exiting.")
        sys.exit(1)
    
    session = Session()
    click.echo(f"Starting red team module (Session: {session.id})")
    asyncio.run(run_redteam("RedTeam-Target", session))
    click.echo(f"Red team scan complete. Findings added to session {session.id}")

@main.group()
def report():
    """Generate reports for a session"""
    pass

@report.command()
@click.option('--session', required=True, help='Session ID')
@click.option('--type', type=click.Choice(['exec', 'full']), required=True, help='Report type')
@click.option('--out', help='Output path')
def generate(session, type, out):
    """Generate PDF report for a session"""
    from pentkit.output.report_engine import ReportEngine
    click.echo(f"Generating {type} report for session {session}...")
    try:
        sess = Session(session_id=session)
        engine = ReportEngine()
        if type == 'full':
            out_path = engine.generate_full_report(sess, out_path=out)
        else:
            out_path = engine.generate_exec_report(sess, out_path=out)
        
        if out_path:
            click.echo(f"Report generated successfully: {out_path}")
        else:
            click.echo("Failed to generate report.")
    except Exception as e:
        click.echo(f"Error: {e}")

@main.group()
def sessions():
    """Manage and list sessions"""
    pass

@sessions.command(name='list')
def sessions_list():
    """List all sessions with status, target, and finding count"""
    all_sessions = Session.list_all()
    click.echo(f"{'ID':<40} {'Name':<20} {'Status':<10} {'Target':<30} {'Findings':<10}")
    click.echo("-" * 110)
    for s in all_sessions:
        targets = ", ".join(s['target']) if s['target'] else "None"
        click.echo(f"{s['id']:<40} {s['name']:<20} {s['status']:<10} {targets:<30} {s['finding_count']:<10}")

@main.group()
def plugins():
    """Manage and run plugins"""
    pass

@plugins.command(name='list')
def plugins_list():
    """List discovered plugins"""
    from pentkit.plugins.plugin_loader import PluginLoader
    loader = PluginLoader()
    discovered = loader.discover_plugins()
    if not discovered:
        click.echo("No plugins found.")
        return
    
    click.echo(f"{'Name':<20} {'Description':<50}")
    click.echo("-" * 70)
    for p in discovered.values():
        click.echo(f"{p.name:<20} {p.description:<50}")

@plugins.command(name='run')
@click.argument('plugin_name')
@click.option('--session', required=True, help='Session ID')
def plugins_run(plugin_name, session):
    """Run a named plugin against an existing session"""
    from pentkit.plugins.plugin_loader import PluginLoader
    click.echo(f"Running plugin {plugin_name} on session {session}...")
    try:
        loader = PluginLoader()
        loader.discover_plugins()
        plugin = loader.get_plugin(plugin_name)
        if not plugin:
            click.echo(f"Plugin {plugin_name} not found.")
            return
        
        sess = Session(session_id=session)
        asyncio.run(plugin.run(sess))
        click.echo(f"Plugin {plugin_name} execution complete.")
    except Exception as e:
        click.echo(f"Error: {e}")

@main.group()
def export():
    """Export findings to different formats"""
    pass

@export.command(name='csv')
@click.option('--session', required=True, help='Session ID')
@click.option('--config', default="config.yaml", help='Path to engagement config YAML')
def export_csv(session, config):
    """Regenerate CSV export for a session"""
    from pentkit.output.csv_exporter import CSVExporter
    
    cfg = get_config(config)
    sess = Session(cfg, session_id=session)
    
    click.echo(f"Regenerating CSV for session {session}...")
    csv_path = asyncio.run(CSVExporter.export_all(sess))
    click.echo(f"CSV exported to: {csv_path}")

if __name__ == '__main__':
    main()
