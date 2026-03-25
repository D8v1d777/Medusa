"""Final validation — post-sanitization."""
import sys, os, ast, importlib
sys.path.insert(0, os.path.dirname(__file__))

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
results = {"pass": 0, "fail": 0}

def check(label, fn):
    try:
        fn()
        print(f"  {PASS} {label}")
        results["pass"] += 1
    except Exception as e:
        print(f"  {FAIL} {label}: {e}")
        results["fail"] += 1

# Syntax check all py files
print("=" * 60)
print("  POST-SANITIZATION VALIDATION")
print("=" * 60)

skip = {'.venv', '.git', '__pycache__', 'node_modules', 'breaches', 'results'}
for dirpath, dirnames, filenames in os.walk('.'):
    dirnames[:] = [d for d in dirnames if d not in skip]
    for f in filenames:
        if f.endswith('.py') and f != '_final_check.py':
            fp = os.path.join(dirpath, f)
            check(f"Syntax: {fp}", lambda fp=fp: ast.parse(open(fp, 'r', encoding='utf-8', errors='ignore').read()))

# Core imports
print("\n  --- Core Imports ---")
for mod in [
    "medusa.engine.core.config",
    "medusa.engine.core.models",
    "medusa.engine.core.session",
    "medusa.engine.core.scope_guard",
    "medusa.engine.core.rate_limiter",
    "medusa.engine.modules.redteam.sovereign_scanner",
    "medusa.engine.modules.network.dark_crawler",
    "medusa.engine.modules.recon.cam_hunter",
    "medusa.engine.modules.recon.leak_lookup",
    "medusa.engine.modules.payloads.rev_gen",
    "medusa.engine.modules.ai.hacker_llm",
    "medusa.engine.modules.ai.triage",
    "medusa.engine.cli",
]:
    check(f"Import: {mod}", lambda m=mod: importlib.import_module(m))

# Anonymity check — scan for identifying strings
print("\n  --- Anonymity Audit ---")
FORBIDDEN = ["Stanford", "David", "Tech Enthusiast", "sk-vefM7N", "b4aae235", "UNLI Network", "Sovereign State-Sponsored"]

violations = []
for dirpath, dirnames, filenames in os.walk('.'):
    dirnames[:] = [d for d in dirnames if d not in skip and d != '.git']
    for f in filenames:
        if f.endswith(('.py', '.md', '.txt', '.toml')) and f != '_final_check.py':
            fp = os.path.join(dirpath, f)
            try:
                content = open(fp, 'r', encoding='utf-8', errors='ignore').read()
                for term in FORBIDDEN:
                    if term.lower() in content.lower():
                        # Exception: luna_persona.md is kept as-is per user requirement
                        if 'luna_persona' in fp or 'long_term_memory' in fp or 'grounding_knowledge' in fp:
                            continue
                        violations.append(f"{fp}: contains '{term}'")
            except:
                pass

if violations:
    for v in violations:
        print(f"  {FAIL} ANONYMITY: {v}")
        results["fail"] += 1
else:
    print(f"  {PASS} No identifying strings found in source files")
    results["pass"] += 1

# Summary
print("\n" + "=" * 60)
total = results['pass'] + results['fail']
health = (results['pass'] / total * 100) if total > 0 else 0
print(f"  PASS: {results['pass']}  |  FAIL: {results['fail']}  |  HEALTH: {health:.0f}%")
print("=" * 60)

sys.exit(1 if results['fail'] > 0 else 0)
