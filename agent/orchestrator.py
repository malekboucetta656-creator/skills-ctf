#!/usr/bin/env python3

from pathlib import Path
import json
import sys

from agent.global_engine.solver import GlobalSolver
from agent.classifier import classify
from agent.context import ChallengeContext, discover_files
from agent.module_adapter import execute


# ============================================================
# MODULES
# ============================================================

MODULES = {
    "web": [
        "agent.scanner",
        "agent.detector",
        "agent.analyzer",
        "agent.web_analyzer",
        "agent.filter_analyzer",
        "agent.client_flow",
        "agent.hypothesis",
    ],

	"pwn": [
	"agent.scanner",
	"agent.detector",
	"agent.hypothesis",
	"agent.pwn_engine",
	],

	 "reverse": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "crypto": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "forensics": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "misc": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "ctf-ai-ml": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "ctf-osint": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "ctf-malware": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "ctf-writeup": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],

    "solve-challenge": [
        "agent.scanner",
        "agent.detector",
        "agent.hypothesis",
    ],
}


# ============================================================
# DISCOVERY
# ============================================================

def discover_challenge(challenge):
    challenge = Path(challenge)

    files = discover_files(str(challenge))

    return files


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_challenge(challenge):
    """
    Normalise la sortie de classifier.py.

    classifier.py retourne actuellement :

        {
            "scores": scores,
            "ranking": ranked,
            "primary": ranked[0][0]
        }

    Le reste du moteur utilise :

        {
            "category": ...,
            "scores": ...
        }
    """

    challenge = Path(challenge)

    result = classify(challenge)

    if not isinstance(result, dict):
        return {
            "category": "unknown",
            "scores": {},
            "ranking": [],
            "raw": result,
        }

    scores = result.get("scores", {})

    primary = result.get("primary")

    # Sécurité :
    # si primary n'existe pas, prendre le meilleur score.
    if not primary and scores:
        primary = max(
            scores,
            key=scores.get
        )

    if not primary:
        primary = "unknown"

    return {
        "category": primary,
        "scores": scores,
        "ranking": result.get("ranking", []),
        "raw": result,
    }


# ============================================================
# MODULE SELECTION
# ============================================================

def select_modules(category):
    """
    Sélectionne les modules correspondant au type de challenge.
    """

    modules = MODULES.get(category)

    if modules is None:
        modules = [
            "agent.scanner",
            "agent.detector",
            "agent.hypothesis",
        ]

    return modules


# ============================================================
# MODULE EXECUTION
# ============================================================

def run_modules(context, modules):
    """
    Exécute les modules sélectionnés via module_adapter.
    """

    results = []

    for module_name in modules:

        print()
        print(f"[MODULE] {module_name}")

        result = execute(
            module_name,
            context.challenge
        )

        results.append(result)

        context.add_result(
            module_name,
            result
        )

        status = result.get("status")

        if status == "EXECUTED":

            print(
                f"[+] {module_name}: "
                f"EXECUTED "
                f"({result.get('entrypoint')})"
            )

            module_result = result.get("result")

            if isinstance(module_result, dict):
                context.merge(module_result)

        elif status == "NO_ENTRYPOINT":

            print(
                f"[-] {module_name}: "
                f"NO ENTRYPOINT"
            )

            context.add_error(
                module_name,
                "No compatible entrypoint"
            )

        elif status == "ERROR":

            print(
                f"[!] {module_name}: "
                f"ERROR"
            )

            error = result.get("error")

            context.add_error(
                module_name,
                error
            )

        else:

            print(
                f"[?] {module_name}: "
                f"{status}"
            )

    return results


# ============================================================
# HYPOTHESIS ENGINE
# ============================================================

def run_hypothesis_engine(context):
    """
    Construit une liste globale d'hypothèses.

    Les hypothèses sont ensuite dédupliquées et triées
    par confiance.

    IMPORTANT :
    une hypothèse avec un score élevé n'est PAS considérée
    comme validée.
    """

    hypotheses = []

    # Hypothèses déjà produites par les modules
    for item in context.hypotheses:

        if isinstance(item, dict):
            hypotheses.append(item)

    # Déduplication
    unique = {}

    for hypothesis in hypotheses:

        name = hypothesis.get(
            "name",
            "unknown"
        )

        confidence = hypothesis.get(
            "confidence",
            0
        )

        reason = hypothesis.get(
            "reason",
            ""
        )

        key = name.lower().strip()

        if key not in unique:

            unique[key] = {
                "name": name,
                "confidence": confidence,
                "reason": reason,
            }

        else:

            # Garder la meilleure confiance
            if confidence > unique[key]["confidence"]:
                unique[key]["confidence"] = confidence

    hypotheses = list(unique.values())

    hypotheses.sort(
        key=lambda x: x.get(
            "confidence",
            0
        ),
        reverse=True
    )

    context.hypotheses = hypotheses

    return hypotheses

# ============================================================
# GLOBAL SOLVER
# ============================================================

def run_global_solver(context):
    """
    Lance le moteur global CyberAI.

    Le GlobalSolver est le contrôleur de haut niveau :
    - priorisation des hypothèses
    - boucle de résolution
    - apprentissage depuis les observations
    - préparation des étapes suivantes

    IMPORTANT :
    une confiance élevée n'est jamais considérée comme
    une validation d'exploitation.
    """

    print()
    print("╔══════════════════════════════════════════╗")
    print("║           GLOBAL SOLVER                  ║")
    print("╚══════════════════════════════════════════╝")
    print()

    try:
        solver = GlobalSolver(context)

        result = solver.run()

        if result is None:
            result = {}

        if isinstance(result, dict):
            context.metadata["global_solver"] = result

            prioritized = result.get("prioritized_hypotheses")

            if isinstance(prioritized, list):
                context.metadata["prioritized_hypotheses"] = prioritized

            status = result.get("status")

            if status:
                context.metadata["solver_status"] = status

            print("[+] GlobalSolver exécuté.")

        else:
            context.metadata["global_solver"] = {
                "result": result
            }

            print("[+] GlobalSolver exécuté.")

        return result

    except Exception as exc:
        print(f"[!] GlobalSolver ERROR: {exc}")

        context.add_error(
            "global_solver",
            str(exc)
        )

        return {
            "status": "ERROR",
            "error": str(exc)
        }

# ============================================================
# EXPERIMENT ENGINE
# ============================================================

def run_experiment_engine(context):
    """
    Lance ExperimentEngine v0.3
    """
    try:
        from agent.experiment_engine import ExperimentEngine

        engine = ExperimentEngine(context)
        results = engine.run()
        return results

    except Exception as exc:
        print(f"[!] ExperimentEngine ERROR: {exc}")
        context.add_error("experiment_engine", str(exc))
        return []

# ============================================================
# EXPLOIT ENGINE
# ============================================================

def run_exploit_engine(context):
    """
    Prépare l'étape exploitation.

    Aucun exploit n'est déclaré valide sans preuve.
    """

    print()
    print("╔══════════════════════════════════════════╗")
    print("║             EXPLOIT ENGINE               ║")
    print("╚══════════════════════════════════════════╝")

    print()

    if not context.experiments:

        print(
            "[-] Aucune expérience validée."
        )

        print(
            "[!] Exploitation différée."
        )

        return []

    return []


# ============================================================
# FLAG ENGINE
# ============================================================

def run_flag_engine(context):
    """
    Recherche finale du flag.

    Pour l'instant :
    - regarde les flags déjà remontés
    - ne fabrique jamais de flag
    """

    print()
    print("╔══════════════════════════════════════════╗")
    print("║               FLAG ENGINE                ║")
    print("╚══════════════════════════════════════════╝")

    print()

    if context.flags:

        print(
            f"[+] {len(context.flags)} "
            f"flag(s) détecté(s)."
        )

        for flag in context.flags:
            print(
                f"    {flag}"
            )

        return context.flags

    print(
        "[-] Aucun flag détecté."
    )

    return []


# ============================================================
# REPORT
# ============================================================

def print_classification(classification):
    print()
    print("╔══════════════════════════════════════════╗")
    print("║        CYBERAI CLASSIFICATION            ║")
    print("╚══════════════════════════════════════════╝")

    print()

    category = classification.get(
        "category",
        "unknown"
    )

    scores = classification.get(
        "scores",
        {}
    )

    ranking = classification.get(
        "ranking",
        []
    )

    print(
        f"category : {category}"
    )

    print()

    print("scores :")

    for name, score in sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        print(
            f"    {name:12} : {score}"
        )

    print()

    if ranking:

        print("ranking :")

        for name, score in ranking:

            print(
                f"    {name:12} : {score}"
            )


def print_hypotheses(hypotheses):

    print()
    print("╔══════════════════════════════════════════╗")
    print("║          HYPOTHESIS ENGINE               ║")
    print("╚══════════════════════════════════════════╝")

    print()

    if not hypotheses:

        print(
            "[-] Aucune hypothèse."
        )

        return

    for hypothesis in hypotheses:

        name = hypothesis.get(
            "name",
            "unknown"
        )

        confidence = hypothesis.get(
            "confidence",
            0
        )

        reason = hypothesis.get(
            "reason",
            ""
        )

        print(
            f"[{confidence}%] {name}"
        )

        if reason:

            print(
                f"      {reason}"
            )

        print()


def print_errors(context):

    if not context.errors:
        return

    print()
    print("[!] ERRORS")

    for error in context.errors:

        if isinstance(error, dict):

            module = error.get(
                "module",
                "unknown"
            )

            message = error.get(
                "error",
                ""
            )

            print(
                f"    {module}: {message}"
            )

        else:

            print(
                f"    {error}"
            )


# ============================================================
# SAVE CONTEXT
# ============================================================

def save_context(context):

    root = Path(
        context.challenge
    )

    output_dir = root / ".cyberai"

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        output_dir /
        "context.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as handle:

        json.dump(
            context.to_dict(),
            handle,
            indent=2,
            ensure_ascii=False,
            default=str
        )

    print()
    print(
        f"[+] Context sauvegardé : "
        f"{output_file}"
    )

    return output_file


# ============================================================
# FINAL REPORT
# ============================================================

def print_final_report(context):

    print()
    print("╔══════════════════════════════════════════╗")
    print("║            FINAL REPORT                  ║")
    print("╚══════════════════════════════════════════╝")
    print()

    # --- Infos générales ---
    print(f"Challenge      : {context.challenge}")
    print(f"Category       : {context.category}")
    print(f"Files          : {len(context.files)}")
    print()

    # --- Résultats PwnEngine s'ils existent ---
    pwn_result = None
    for name, result in context.module_results.items():
        if "pwn_engine" in name and isinstance(result, dict):
            inner = result.get("result")
            if isinstance(inner, dict):
                pwn_result = inner
                break

    if pwn_result:
        print("── PwnEngine Analysis ─────────────────────")
        binaries = pwn_result.get("binaries", [])
        sources = pwn_result.get("sources", [])
        protections = pwn_result.get("protections", {})
        primitives = pwn_result.get("primitives", [])
        symbols = pwn_result.get("symbols", [])
        strings = pwn_result.get("strings", [])
        targets = pwn_result.get("targets", [])

        if binaries:
            print(f"Binaries       : {len(binaries)}")
            for b in binaries:
                print(f"  • {b}")

        if sources:
            print(f"Sources        : {len(sources)}")
            for s in sources:
                print(f"  • {s}")

        if protections:
            print("Protections    :")
            for binary, info in protections.items():
                print(f"  [{binary}]")
                for line in str(info).splitlines():
                    print(f"    {line}")

        if primitives:
            print(f"Primitives     : {len(primitives)}")
            for p in primitives:
                if isinstance(p, dict):
                    print(f"  • {p.get('type', '?')} ({p.get('name', p.get('source', ''))})")

        if symbols:
            print(f"Interesting symbols : {len(symbols)}")
            for s in symbols[:10]:
                if isinstance(s, dict):
                    print(f"  • {s.get('name')} @ {s.get('address')}")

        if targets:
            print(f"Targets        : {len(targets)}")
            for t in targets:
                if isinstance(t, dict):
                    print(f"  • {t.get('type')} → {t.get('variable', t.get('source', ''))}")

        if strings:
            print(f"Interesting strings : {len(strings)}")
            for s in strings[:8]:
                if isinstance(s, dict):
                    print(f"  • {s.get('value')}")
        print()

    # --- Hypothèses ---
    print("── Hypotheses ─────────────────────────────")
    if not context.hypotheses:
        print("  (aucune)")
    else:
        for h in context.hypotheses:
            if isinstance(h, dict):
                conf = h.get("confidence", h.get("solver_score", "?"))
                name = h.get("name", "unknown")
                reason = h.get("reason", "")
                print(f"  [{conf}%] {name}")
                if reason:
                    print(f"       {reason}")
    print()

    # --- Flags ---
    print("── Flags ──────────────────────────────────")
    if context.flags:
        for f in context.flags:
            print(f"  🚩 {f}")
    else:
        print("  (aucun flag détecté)")
    print()

    # --- Erreurs ---
    if context.errors:
        print("── Errors ─────────────────────────────────")
        for e in context.errors:
            if isinstance(e, dict):
                print(f"  • {e.get('module')}: {e.get('error')}")
            else:
                print(f"  • {e}")
        print()

    print("════════════════════════════════════════════")

# ============================================================
# MAIN ENGINE
# ============================================================

def run(challenge):

    challenge = Path(
        challenge
    ).expanduser().resolve()

    print()
    print("╔══════════════════════════════════════════╗")
    print("║             CYBERAI V3                  ║")
    print("║          GLOBAL CTF ENGINE               ║")
    print("╚══════════════════════════════════════════╝")

    print()

    print(
        f"[+] Challenge : {challenge}"
    )

    # --------------------------------------------------------
    # CONTEXT
    # --------------------------------------------------------

    context = ChallengeContext(
        challenge=str(challenge)
    )

    # --------------------------------------------------------
    # DISCOVERY
    # --------------------------------------------------------

    print()
    print("╔══════════════════════════════════════════╗")
    print("║             DISCOVERY                   ║")
    print("╚══════════════════════════════════════════╝")

    files = discover_challenge(
        challenge
    )

    context.files = files

    print()
    print(
        f"[+] Files discovered : "
        f"{len(files)}"
    )

    # --------------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------------

    classification = classify_challenge(
        challenge
    )

    context.category = classification.get(
        "category",
        "unknown"
    )

    context.scores = classification.get(
        "scores",
        {}
    )

    context.metadata[
        "classification"
    ] = classification

    print_classification(
        classification
    )

    # --------------------------------------------------------
    # MODULE SELECTION
    # --------------------------------------------------------

    modules = select_modules(
        context.category
    )

    context.metadata[
        "selected_modules"
    ] = modules

    print()
    print("╔══════════════════════════════════════════╗")
    print("║          MODULE SELECTION                ║")
    print("╚══════════════════════════════════════════╝")

    print()

    print(
        f"[+] Category : "
        f"{context.category}"
    )

    print()

    for module in modules:

        print(
            f"    - {module}"
        )

    # --------------------------------------------------------
    # MODULE EXECUTION
    # --------------------------------------------------------

    print()
    print("╔══════════════════════════════════════════╗")
    print("║           MODULE EXECUTION              ║")
    print("╚══════════════════════════════════════════╝")

    run_modules(
        context,
        modules
    )

    # --------------------------------------------------------
    # HYPOTHESIS
    # --------------------------------------------------------

    hypotheses = run_hypothesis_engine(
        context
    )

    print_hypotheses(
        hypotheses
    )

    # --------------------------------------------------------
    # EXPERIMENT
    # --------------------------------------------------------

    # --------------------------------------------------------
    # GLOBAL SOLVER
    # --------------------------------------------------------

    context.metadata["engine"] = "CyberAI Global Solver"
    context.metadata["engine_version"] = "V4"
    context.metadata["autonomous"] = True
    context.metadata["validation_required"] = True

    solver_result = run_global_solver(
        context
    )

    context.metadata["solver_result"] = solver_result

    experiments = run_experiment_engine(
        context
    )

    context.experiments = experiments

    # --------------------------------------------------------
    # EXPLOIT
    # --------------------------------------------------------

    exploits = run_exploit_engine(
        context
    )

    context.exploits = exploits

    # --------------------------------------------------------
    # FLAG
    # --------------------------------------------------------

    flags = run_flag_engine(
        context
    )

    context.flags = flags

    # --------------------------------------------------------
    # ERRORS
    # --------------------------------------------------------

    print_errors(
        context
    )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print_final_report(
        context
    )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    save_context(
        context
    )

    return context


# ============================================================
# CLI
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "  python3 -m agent.orchestrator "
            "<challenge>"
        )

        sys.exit(1)

    challenge = sys.argv[1]

    try:

        run(challenge)

    except KeyboardInterrupt:

        print()
        print(
            "[!] Interrupted."
        )

        sys.exit(130)

    except Exception as exc:

        print()
        print(
            f"[!] FATAL ERROR: {exc}"
        )

        raise


if __name__ == "__main__":
    main()
