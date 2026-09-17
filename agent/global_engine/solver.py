#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import time
from typing import Any


class GlobalSolver:
    """
    Boucle de résolution globale CyberAI.

    Principe :

        DISCOVER
            ↓
        ANALYZE
            ↓
        HYPOTHESIZE
            ↓
        EXPERIMENT
            ↓
        OBSERVE
            ↓
        VALIDATE
            ↓
        SOLUTION ?

    Une hypothèse n'est jamais une preuve.
    """

    MAX_ROUNDS = 12

    def __init__(self, context):
        self.context = context
        self.history = []

    # ---------------------------------------------------------
    # Utilitaires
    # ---------------------------------------------------------

    @staticmethod
    def _key(value: Any) -> str:
        raw = repr(value).encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()[:16]

    def _record(self, event, data=None):
        item = {
            "event": event,
            "timestamp": time.time(),
            "data": data or {},
        }

        self.history.append(item)

        if not isinstance(
            self.context.metadata.get("solver_history"),
            list,
        ):
            self.context.metadata["solver_history"] = []

        self.context.metadata["solver_history"].append(item)

    # ---------------------------------------------------------
    # Etat
    # ---------------------------------------------------------

    def _flags_found(self):
        return bool(self.context.flags)

    def _validated_experiments(self):
        return [
            x
            for x in self.context.experiments
            if isinstance(x, dict)
            and x.get("validated") is True
        ]

    def _rejected_hypotheses(self):
        rejected = set()

        for experiment in self.context.experiments:
            if not isinstance(experiment, dict):
                continue

            if experiment.get("status") == "REJECTED":
                rejected.add(
                    str(
                        experiment.get(
                            "hypothesis",
                            "",
                        )
                    ).lower()
                )

        return rejected

    # ---------------------------------------------------------
    # Priorité
    # ---------------------------------------------------------

    def prioritize(self):
        """
        Priorité dynamique.

        Ce n'est pas simplement le confidence score.
        Une piste déjà rejetée descend fortement.
        Une piste produisant des observations concrètes monte.
        """

        rejected = self._rejected_hypotheses()

        scored = []

        for hypothesis in self.context.hypotheses:

            if not isinstance(hypothesis, dict):
                continue

            name = str(
                hypothesis.get(
                    "name",
                    "unknown",
                )
            )

            confidence = float(
                hypothesis.get(
                    "confidence",
                    0,
                )
            )

            score = confidence

            if name.lower() in rejected:
                score -= 100

            reason = str(
                hypothesis.get(
                    "reason",
                    "",
                )
            ).lower()

            # Les hypothèses avec des indicateurs techniques
            # concrets sont légèrement favorisées.
            indicators = (
                "sink",
                "source",
                "input",
                "overflow",
                "format",
                "parser",
                "sql",
                "xss",
                "dom",
                "elf",
                "buffer",
                "crypto",
                "encoding",
                "archive",
                "metadata",
            )

            score += sum(
                2
                for indicator in indicators
                if indicator in reason
            )

            item = dict(hypothesis)
            item["solver_score"] = score

            scored.append(item)

        scored.sort(
            key=lambda x: x.get(
                "solver_score",
                0,
            ),
            reverse=True,
        )

        return scored

    # ---------------------------------------------------------
    # Détection de solution
    # ---------------------------------------------------------

    def check_solution(self):
        if self._flags_found():
            self._record(
                "FLAG_FOUND",
                {
                    "count": len(
                        self.context.flags
                    )
                },
            )
            return True

        validated = self._validated_experiments()

        if validated:
            self._record(
                "VALIDATED_EXPERIMENT",
                {
                    "count": len(validated)
                },
            )

        return False

    # ---------------------------------------------------------
    # Génération de nouvelles pistes
    # ---------------------------------------------------------

    def generate_fallback_hypotheses(self):
        """
        Génération générique de pistes lorsque les hypothèses
        initiales sont insuffisantes.

        Aucun challenge n'est hardcodé.
        """

        category = str(
            self.context.category
        ).lower()

        candidates = []

        if category == "web":
            candidates.extend(
                [
                    {
                        "name": "Input Discovery",
                        "confidence": 45,
                        "reason": (
                            "Recherche générique des "
                            "entrées contrôlables."
                        ),
                    },
                    {
                        "name": "Client-side Analysis",
                        "confidence": 40,
                        "reason": (
                            "Analyse du JavaScript "
                            "exécuté côté client."
                        ),
                    },
                    {
                        "name": "Server-side Data Flow",
                        "confidence": 35,
                        "reason": (
                            "Recherche du flux source → "
                            "traitement → sink."
                        ),
                    },
                ]
            )

        elif category == "pwn":
            candidates.extend(
                [
                    {
                        "name": "Binary Vulnerability Analysis",
                        "confidence": 50,
                        "reason": (
                            "Analyse générique du binaire "
                            "et des primitives d'exploitation."
                        ),
                    },
                    {
                        "name": "Memory Corruption",
                        "confidence": 40,
                        "reason": (
                            "Recherche de corruption mémoire."
                        ),
                    },
                    {
                        "name": "Input Boundary Analysis",
                        "confidence": 35,
                        "reason": (
                            "Recherche des limites de "
                            "lecture/écriture."
                        ),
                    },
                ]
            )

        elif category == "reverse":
            candidates.extend(
                [
                    {
                        "name": "Static Binary Analysis",
                        "confidence": 50,
                        "reason": (
                            "Analyse statique du programme."
                        ),
                    },
                    {
                        "name": "String and Constant Analysis",
                        "confidence": 40,
                        "reason": (
                            "Recherche de chaînes et constantes "
                            "intéressantes."
                        ),
                    },
                ]
            )

        elif category == "crypto":
            candidates.extend(
                [
                    {
                        "name": "Encoding Analysis",
                        "confidence": 45,
                        "reason": (
                            "Recherche d'encodages ou "
                            "transformations réversibles."
                        ),
                    },
                    {
                        "name": "Cryptographic Structure Analysis",
                        "confidence": 45,
                        "reason": (
                            "Analyse de la construction "
                            "cryptographique."
                        ),
                    },
                ]
            )

        elif category == "forensics":
            candidates.extend(
                [
                    {
                        "name": "Artifact Analysis",
                        "confidence": 50,
                        "reason": (
                            "Recherche d'informations "
                            "cachées dans les artefacts."
                        ),
                    },
                    {
                        "name": "Metadata Analysis",
                        "confidence": 40,
                        "reason": (
                            "Analyse des métadonnées."
                        ),
                    },
                    {
                        "name": "File Carving",
                        "confidence": 35,
                        "reason": (
                            "Recherche de données "
                            "encapsulées ou supprimées."
                        ),
                    },
                ]
            )

        elif category == "ctf-ai-ml":
            candidates.extend(
                [
                    {
                        "name": "Model Weight Manipulation",
                        "confidence": 45,
                        "reason": (
                            "Perturbation des poids du modèle."
                        ),
                    },
                    {
                        "name": "Adversarial Example Generation",
                        "confidence": 40,
                        "reason": (
                            "Génération d'exemples adverses "
                            "pour tester la robustesse."
                        ),
                    },
                    {
                        "name": "Prompt Injection",
                        "confidence": 35,
                        "reason": (
                            "Injection de prompts dans les LLM."
                        ),
                    },
                ]
            )

        elif category == "ctf-osint":
            candidates.extend(
                [
                    {
                        "name": "Social Media Enumeration",
                        "confidence": 45,
                        "reason": (
                            "Collecte d'informations depuis "
                            "les réseaux sociaux."
                        ),
                    },
                    {
                        "name": "Geolocation Analysis",
                        "confidence": 40,
                        "reason": (
                            "Détermination géographique "
                            "à partir d'indices."
                        ),
                    },
                    {
                        "name": "Username Metadata Mining",
                        "confidence": 35,
                        "reason": (
                            "Minage de métadonnées depuis "
                            "les noms d'utilisateur."
                        ),
                    },
                ]
            )

        elif category == "ctf-malware":
            candidates.extend(
                [
                    {
                        "name": "C2 Traffic Analysis",
                        "confidence": 45,
                        "reason": (
                            "Analyse du trafic command-and-control."
                        ),
                    },
                    {
                        "name": "Dynamic Analysis",
                        "confidence": 40,
                        "reason": (
                            "Analyse dynamique du malware "
                            "via strace/ltrace."
                        ),
                    },
                    {
                        "name": "YARA Rules Generation",
                        "confidence": 35,
                        "reason": (
                            "Création de règles YARA pour "
                            "la détection."
                        ),
                    },
                ]
            )

        elif category == "ctf-writeup":
            candidates.extend(
                [
                    {
                        "name": "Writeup Generation",
                        "confidence": 50,
                        "reason": (
                            "Génération de writeup structuré "
                            "avec métadonnées."
                        ),
                    },
                    {
                        "name": "Solution Steps Documentation",
                        "confidence": 45,
                        "reason": (
                            "Documentation des étapes de "
                            "solution."
                        ),
                    },
                ]
            )

        elif category == "solve-challenge":
            candidates.extend(
                [
                    {
                        "name": "Challenge Analysis",
                        "confidence": 50,
                        "reason": (
                            "Analyse et décomposition du "
                            "challenge."
                        ),
                    },
                    {
                        "name": "Skill Delegation",
                        "confidence": 45,
                        "reason": (
                            "Délégation aux skills category."
                        ),
                    },
                ]
            )

        else:
            candidates.extend(
                [
                    {
                        "name": "Artifact Discovery",
                        "confidence": 40,
                        "reason": (
                            "Recherche générique d'artefacts."
                        ),
                    },
                    {
                        "name": "Hidden Data Analysis",
                        "confidence": 35,
                        "reason": (
                            "Recherche de données cachées."
                        ),
                    },
                ]
            )

        existing = {
            str(
                x.get(
                    "name",
                    "",
                )
            ).lower()
            for x in self.context.hypotheses
            if isinstance(x, dict)
        }

        added = []

        for candidate in candidates:
            if candidate["name"].lower() in existing:
                continue

            self.context.hypotheses.append(
                candidate
            )

            existing.add(
                candidate["name"].lower()
            )

            added.append(candidate)

        return added

    # ---------------------------------------------------------
    # Boucle principale
    # ---------------------------------------------------------

    def run(self):
        self._record(
            "SOLVER_START",
            {
                "category": self.context.category,
                "files": len(
                    self.context.files
                ),
            },
        )

        for round_number in range(
            1,
            self.MAX_ROUNDS + 1,
        ):

            print()
            print(
                "╔══════════════════════════════════════╗"
            )
            print(
                f"║ GLOBAL SOLVER ROUND {round_number:<14}║"
            )
            print(
                "╚══════════════════════════════════════╝"
            )

            self._record(
                "ROUND_START",
                {
                    "round": round_number,
                },
            )

            # -------------------------------------------------
            # Flag déjà trouvé ?
            # -------------------------------------------------

            if self.check_solution():
                print(
                    "[+] Solution déjà trouvée."
                )
                break

            # -------------------------------------------------
            # Ajouter des pistes si nécessaire
            # -------------------------------------------------

            added = self.generate_fallback_hypotheses()

            if added:
                print(
                    f"[+] Nouvelles hypothèses : "
                    f"{len(added)}"
                )

            # -------------------------------------------------
            # Priorisation
            # -------------------------------------------------

            prioritized = self.prioritize()

            self.context.metadata[
                "prioritized_hypotheses"
            ] = prioritized

            if prioritized:
                print(
                    "[+] Hypothèse prioritaire : "
                    f"{prioritized[0].get('name')}"
                )

            self._record(
                "PRIORITIZATION",
                {
                    "count": len(prioritized),
                },
            )

            # -------------------------------------------------
            # Pas d'expérience automatique ici.
            #
            # Le solver prépare le travail et laisse les
            # moteurs spécialisés produire les observations.
            # -------------------------------------------------

            if self.context.experiments:

                last = self.context.experiments[-1]

                if isinstance(last, dict):

                    status = last.get(
                        "status"
                    )

                    print(
                        f"[+] Dernière expérience : "
                        f"{status}"
                    )

                    if status == "EVIDENCE_FOUND":
                        print(
                            "[+] Evidence trouvée."
                        )

                    elif status == "REJECTED":
                        print(
                            "[-] Piste rejetée."
                        )

            self._record(
                "ROUND_END",
                {
                    "round": round_number,
                    "flags": len(
                        self.context.flags
                    ),
                    "experiments": len(
                        self.context.experiments
                    ),
                },
            )

            # Pour l'instant, une seule passe du moteur global.
            # Les moteurs spécialisés seront branchés ensuite.
            break

        self.context.metadata[
            "solver_status"
        ] = (
            "SOLVED"
            if self.context.flags
            else "IN_PROGRESS"
        )

        self._record(
            "SOLVER_END",
            {
                "status": self.context.metadata[
                    "solver_status"
                ]
            },
        )

        return self.context
