#!/usr/bin/env python3
"""
UniversalAgent - Orchestrateur 100% coverage ambition
- Isolation totale: n'importe quel import de pwn_engine/gdb_engine est en lecture seule
- Pipeline: Discovery -> Classification -> LLMAnalyzer -> AttackEngine -> FlagHunter -> Report
- 100% = on tente TOUS les types, on valide déterministiquement, on n'hallucine jamais
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
import json
import sys

from agent.classifier import classify
from agent.context import ChallengeContext, discover_files
from agent.universal.llm_analyzer import LLMAnalyzer
from agent.universal.attack_engine import AttackEngine
from agent.universal.flag_hunter import FlagHunter

class UniversalAgent:
    VERSION = "0.1.0"

    def __init__(self, challenge: str):
        self.challenge = Path(challenge).expanduser().resolve()
        self.context = ChallengeContext(challenge=str(self.challenge))

    def discover(self):
        files = discover_files(str(self.challenge))
        self.context.files = files
        return files

    def classify_challenge(self):
        result = classify(self.challenge)
        cat = result.get("primary","unknown")
        self.context.category = cat
        self.context.scores = result.get("scores",{})
        self.context.metadata["classification"] = result
        return result

    def run_llm_analysis(self):
        ctx_dict = self.context.to_dict() if hasattr(self.context, "to_dict") else {
            "category": self.context.category,
            "files": self.context.files,
            "challenge": str(self.challenge)
        }
        analyzer = LLMAnalyzer(str(self.challenge))
        res = analyzer.analyze(ctx_dict)
        self.context.hypotheses = res.get("hypotheses",[])
        self.context.metadata["llm_analysis"] = res
        return res

    def run_attacks(self):
        engine = AttackEngine(str(self.challenge))
        res = engine.run(self.context.hypotheses)
        self.context.experiments = res.get("results",[])
        self.context.metadata["attack_engine"] = res
        return res

    def hunt_flags(self):
        hunter = FlagHunter(str(self.challenge))
        ctx_dict = self.context.to_dict() if hasattr(self.context, "to_dict") else self.context.__dict__
        res = hunter.run(ctx_dict)
        self.context.flags = [f["flag"] for f in res.get("flags",[])]
        self.context.metadata["flag_hunter"] = res
        return res

    def save(self):
        out_dir = self.challenge / ".cyberai"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "universal_context.json"
        data = self.context.to_dict() if hasattr(self.context, "to_dict") else self.context.__dict__
        # enrich
        data["universal_version"] = self.VERSION
        data["engine"] = "UniversalAgent"
        with out.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return out

    def print_report(self):
        print("\n╔══════════════════════════════════════════╗")
        print("║         UNIVERSAL AGENT V0.1             ║")
        print("║   LLM + Validation Déterministe 100%     ║")
        print("╚══════════════════════════════════════════╝\n")
        print(f"Challenge : {self.challenge}")
        print(f"Category  : {self.context.category}")
        print(f"Files     : {len(self.context.files)}")
        print("\n── Hypothèses (LLMAnalyzer) ──")
        for h in self.context.hypotheses:
            print(f"  [{h.get('confidence')}%] {h.get('name')} -> {h.get('attack')} ({h.get('validator')})")
            print(f"       {h.get('reason')}")
        print("\n── Validation (AttackEngine) ──")
        atk = self.context.metadata.get("attack_engine",{})
        for r in atk.get("results",[]):
            mark = "✅" if r["status"]=="VALIDATED" else "❌"
            print(f"  {mark} {r['hypothesis']} : {r['status']} - {r['validation']}")
        print("\n── Flags (FlagHunter) ──")
        fh = self.context.metadata.get("flag_hunter",{})
        if fh.get("flags"):
            for f in fh["flags"]:
                ver = "✓" if f.get("verified") else "?"
                print(f"  {ver} {f['flag']} (src: {f['source']})")
        else:
            print("  (aucun flag vérifié - normal si exploit non exécuté)")
        print("\n── Note ──")
        print("  100% = couverture tous types + validation. Aucun flag hallucine.")
        print("  Prochaine étape: exécuter exploit validé pour obtenir flag réel.\n")

    def run(self) -> ChallengeContext:
        print(f"[+] UniversalAgent sur {self.challenge}")
        self.discover()
        print(f"[+] Files: {len(self.context.files)}")
        cls = self.classify_challenge()
        print(f"[+] Classification: {cls.get('primary')} {cls.get('scores')}")
        llm = self.run_llm_analysis()
        print(f"[+] LLM hypotheses: {len(llm.get('hypotheses',[]))} (llm_used={llm.get('llm_used')})")
        atk = self.run_attacks()
        print(f"[+] Attacks validated: {atk.get('validated')}/{atk.get('total')}")
        flags = self.hunt_flags()
        print(f"[+] Flags hunted: {flags.get('count')}")
        self.print_report()
        out = self.save()
        print(f"[+] Sauvé: {out}")
        return self.context

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 -m agent.universal.universal_agent <challenge>")
        sys.exit(1)
    agent = UniversalAgent(sys.argv[1])
    agent.run()

if __name__ == "__main__":
    main()
