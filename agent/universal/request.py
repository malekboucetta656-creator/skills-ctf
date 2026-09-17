#!/usr/bin/env python3
"""
Alternative Request API pour UniversalAgent
Pas le même appel que `python3 -m agent.universal.universal_agent <path>`
Ici: API fonctionnelle + JSON + batch
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
import json

from agent.universal.universal_agent import UniversalAgent

def universal_request(challenge: str, mode: str = "full", hunt_only: bool = False) -> dict[str, Any]:
    """
    Nouvelle API:
      challenge: path
      mode: "full" | "classify" | "hunt" | "attack"
      hunt_only: si True, ne fait que FlagHunter
    Retourne dict JSON sérialisable
    """
    agent = UniversalAgent(challenge)
    if mode == "classify":
        agent.discover()
        cls = agent.classify_challenge()
        return {"request": "classify", "challenge": str(agent.challenge), "classification": cls}

    if mode == "hunt":
        agent.discover()
        agent.classify_challenge()
        # hunt sans LLM
        res = agent.hunt_flags()
        return {"request": "hunt", "challenge": str(agent.challenge), "flags": res}

    if mode == "attack":
        agent.discover()
        agent.classify_challenge()
        llm = agent.run_llm_analysis()
        atk = agent.run_attacks()
        return {"request": "attack", "challenge": str(agent.challenge), "hypotheses": llm["hypotheses"], "attack": atk}

    # full
    ctx = agent.run()
    return {
        "request": "full",
        "challenge": str(agent.challenge),
        "category": ctx.category,
        "hypotheses": ctx.hypotheses,
        "attack": ctx.metadata.get("attack_engine"),
        "flags": ctx.metadata.get("flag_hunter"),
        "saved": str(agent.challenge / ".cyberai" / "universal_context.json")
    }

def batch_request(challenges: list[str]) -> list[dict]:
    out = []
    for c in challenges:
        try:
            out.append(universal_request(c, mode="full"))
        except Exception as e:
            out.append({"challenge": c, "error": str(e)})
    return out

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage alternative:")
        print("  python3 -m agent.universal.request classify <challenge>")
        print("  python3 -m agent.universal.request hunt <challenge>")
        print("  python3 -m agent.universal.request attack <challenge>")
        print("  python3 -m agent.universal.request full <challenge>")
        print("  python3 -m agent.universal.request batch <c1> <c2> ...")
        sys.exit(1)
    mode = sys.argv[1]
    if mode == "batch":
        res = batch_request(sys.argv[2:])
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
    else:
        chal = sys.argv[2]
        res = universal_request(chal, mode=mode)
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
