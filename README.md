# CyberAI

**Assistant CTF universel** — analyse, hypothèses, validation déterministe et chasse de flags.

CyberAI comprend un challenge, détecte les primitives, propose des pistes classées par confiance et **ne valide jamais sans preuve d'exécution**. Couvre pwn / rev / web / crypto / forensics / stego / misc.

> ⚠️ Usage **légal et éthique uniquement** (CTF, labs, recherche autorisée). Aucun flag n'est halluciné.

---

## État actuel (v0.3)

| Fonctionnalité | Statut | Notes |
|---|---|---|
| Classification | ✅ | `agent/classifier.py` — web/pwn/rev/crypto/forensics/misc |
| PwnEngine | ✅ | `agent/pwn_engine.py` — ELF, protections, symbols, primitives |
| GDBEngine | ✅ | `agent/gdb_engine.py` v1.2 — arch, fonctions, locals, mémoire |
| Hypothèses | ✅ | `agent/hypothesis.py` — déduplication + tri confiance |
| GlobalSolver | ✅ | priorisation + boucle de résolution |
| **UniversalAgent** | ✅ **NEW** | `agent/universal/` — LLM + validation 100% coverage |
| ExperimentEngine | 🚧 | `agent/experiment_engine.py` — validation en cours |
| FlagHunter | ✅ | `agent/universal/flag_hunter.py` + `agent/flag_engine.py` — regex vérifiée |
| Web / Crypto / Rev | 🚧 partiel | via UniversalAgent |

### Nouveau : UniversalAgent v0.1 (`agent/universal/`)

Isolation totale — 0 modification de `pwn_engine` / `gdb_engine` / `orchestrator`.

```
agent/universal/
├── universal_agent.py  — orchestrateur (Discovery → Classify → LLM → Attack → Flag)
├── llm_analyzer.py     — LLM + fallback heuristique, 0 flag inventé
├── attack_engine.py    — validators déterministes (balance overflow, RAR5 ADS)
├── flag_hunter.py      — chasse regex sur artefacts réels uniquement
└── request.py          — API alternative (classify/hunt/attack/full/batch)
```

**Principes :**
- 100% = couverture tous types + validation, pas 100% auto-solve
- LLM propose, le déterministe dispose (`VALIDATED` seulement si `subprocess` OK)
- Aucun flag déclaré sans `verified=True`

---

## Installation

```bash
git clone https://github.com/malekboucetta656-creator/skills-ctf.git
cd skills-ctf
pip install -r requirements.txt  # ou pip install -e .
```

## Usage

### 1. Orchestrateur classique
```bash
PYTHONPATH=. python3 -m agent.orchestrator <challenge_dir>
```

### 2. UniversalAgent (recommandé)
```bash
# Full pipeline
PYTHONPATH=. python3 -m agent.universal.universal_agent <challenge_dir>

# API granulaire (nouveau)
PYTHONPATH=. python3 -m agent.universal.request classify <challenge>
PYTHONPATH=. python3 -m agent.universal.request attack <challenge>
PYTHONPATH=. python3 -m agent.universal.request hunt <challenge>
PYTHONPATH=. python3 -m agent.universal.request full <challenge>
PYTHONPATH=. python3 -m agent.universal.request batch <c1> <c2> <c3>

# Python
from agent.universal.request import universal_request
universal_request("./challenge/roulette", mode="full")
```

### 3. Modules isolés
```bash
PYTHONPATH=. python3 -m agent.pwn_engine ./challenge/roulette
PYTHONPATH=. python3 -m agent.gdb_engine ./challenge/roulette/chal
PYTHONPATH=. python3 -m agent.flag_engine ./challenge
```

## Exemples vérifiés

| Challenge | Catégorie | Résultat |
|---|---|---|
| `roulette` (`chal.c` pwn 1-byte write) | pwn | `92% one_byte_write` → `✅ VALIDATED` |
| `Flag.rar` (RAR5 ADS `Flag.txt.txt:real_flag.txt`) | forensics | `88% rar_ads_stm` → `✅ VALIDATED` |
| `whatsNew` (Node.js) | web | `web_sqli_xss 70%` → `✅ VALIDATED` |

Sortie JSON dans `<challenge>/.cyberai/universal_context.json`.

## Architecture

```
challenge/
  → Classifier (scores extensions + keywords)
  → UniversalAgent
      → LLMAnalyzer (hypothèses typées + validator)
      → AttackEngine (subprocess / GDB / unrar / binwalk)
      → FlagHunter (regex flag{} / ctf{} / TFC{} sur artefacts réels)
  → Report (confiance ≠ validation)
```

## Développement

- Ne jamais modifier `pwn_engine.py` / `gdb_engine.py` pour une nouvelle feature — créer `agent/universal/` ou `agent/skills/`
- Toute hypothèse doit avoir un `validator` déterministe
- `pre-commit` / tests : `pytest -q`

## License

MIT — voir `LICENSE`.

## Auteur

Malek Boucetta — [@malekboucetta656-creator](https://github.com/malekboucetta656-creator)
