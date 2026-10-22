# Framework
<!-- VICTORIAN-MOURNING-GALLERY -->

<p align="center">
  <strong>THE MOURNING GALLERY</strong><br />
  <em>Victorian veils · Renaissance shadows · antique oil portraits</em>
</p>

<p align="center">
  <a href="https://commons.wikimedia.org/wiki/Special:FilePath/Malarz_francuski_XIX_wiek_-_Portrait_of_a_woman_with_a_veil_-_M.Ob.1273_MNW_-_National_Museum_in_Warsaw.jpg"><img src="https://commons.wikimedia.org/wiki/Special:FilePath/Malarz_francuski_XIX_wiek_-_Portrait_of_a_woman_with_a_veil_-_M.Ob.1273_MNW_-_National_Museum_in_Warsaw.jpg" alt="Portrait of a woman with a veil" width="30%" /></a>
  <a href="https://commons.wikimedia.org/wiki/Special:FilePath/Boldini_-_lady-with-a-black-hat.jpg"><img src="https://commons.wikimedia.org/wiki/Special:FilePath/Boldini_-_lady-with-a-black-hat.jpg" alt="Lady in a black hat and veil" width="30%" /></a>
  <a href="https://commons.wikimedia.org/wiki/Special:FilePath/Jacob_Adriaensz_Backer_-_Tronie_of_a_woman_with_a_black_veil,_l19038-b3vt9-1.jpg"><img src="https://commons.wikimedia.org/wiki/Special:FilePath/Jacob_Adriaensz_Backer_-_Tronie_of_a_woman_with_a_black_veil,_l19038-b3vt9-1.jpg" alt="A woman in a black veil" width="30%" /></a>
</p>

---
<!-- /VICTORIAN-MOURNING-GALLERY -->


Integrated security assessment platform. CLI-driven, modular, extensible.

## Quick Start

```bash
# Activate environment
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Full assessment
python -m medusa.engine.cli scan <target> -t all --report

# Network enumeration
python -m medusa.engine.cli scan 192.168.1.0/24 -t network

# Web assessment with deep policy
python -m medusa.engine.cli scan https://target.internal -t web -p deep
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `-t, --type` | `web`, `network`, `ad`, `all` (default: `all`) |
| `-p, --policy` | `quick`, `standard`, `deep`, `api`, `cve` |
| `-x, --exploit` | Enable POC generation for findings |
| `--report` | Generate report after completion |
| `--no-ai` | Disable AI-assisted triage |

## Deployment

```bash
pip install -r requirements.txt
pip install -e ./medusa/engine
python -m medusa.engine.cli --help
```

---
**Authorized use only.**
