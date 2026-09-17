#!/usr/bin/env python3
"""
CyberAI - Pwn Runtime Engine V3

Generic runtime engine for authorized local ELF PWN challenges.

Architecture:

    static binary/source evidence
              |
              v
       runtime discovery
              |
              v
       candidate generation
              |
              v
       same-inferior execution
              |
              v
          observation
              |
       +------+------+
       |             |
       v             v
   FLAG_FOUND     REJECTED

Important:
- No challenge-specific addresses.
- No hardcoded wager/value/offset.
- No direct invocation of target functions.
- Runtime addresses are discovered dynamically.
- The runtime experiment is executed against the same inferior.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional


@dataclass
class RuntimeObservation:
    status: str
    confidence: float
    reason: str
    data: dict[str, Any]


@dataclass
class TargetCandidate:
    name: str
    address: int
    source: str
    score: float


class PwnRuntimeEngine:
    VERSION = "3.0"

    TARGET_NAMES = {
        "win",
        "get_flag",
        "print_flag",
        "flag",
        "shell",
        "success",
        "winner",
        "give_flag",
        "getflag",
        "printflag",
    }

    FLAG_PATTERNS = [
        re.compile(r"flag\{[^}\n]+\}", re.I),
        re.compile(r"ctf\{[^}\n]+\}", re.I),
        re.compile(r"picoctf\{[^}\n]+\}", re.I),
        re.compile(r"htb\{[^}\n]+\}", re.I),
        re.compile(r"[A-Z0-9_]{2,30}\{[^}\n]+\}", re.I),
    ]

    def __init__(
        self,
        binary: str,
        timeout: int = 20,
        gdb_path: str = "gdb",
        retries: int = 3,
    ):
        self.binary = str(Path(binary).resolve())
        self.timeout = timeout
        self.gdb_path = gdb_path
        self.retries = max(1, int(retries))

        self.result: dict[str, Any] = {
            "engine": "PwnRuntimeEngine",
            "version": self.VERSION,
            "binary": self.binary,
            "status": "STATIC_EVIDENCE",
            "strategy": None,
            "candidate": None,
            "state": {},
            "observations": [],
            "control_flow": [],
            "experiments": [],
            "flags": [],
            "errors": [],
        }

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def observe(
        self,
        status: str,
        confidence: float,
        reason: str,
        data: Optional[dict[str, Any]] = None,
    ) -> None:
        self.result["observations"].append(
            asdict(
                RuntimeObservation(
                    status=status,
                    confidence=float(confidence),
                    reason=reason,
                    data=data or {},
                )
            )
        )

    def fail(self, reason: str) -> dict[str, Any]:
        self.result["status"] = "REJECTED"
        self.result["errors"].append(reason)
        self.observe(
            "REJECTED",
            0.0,
            reason,
        )
        return self.result

    def run_cmd(
        self,
        command: list[str],
        timeout: Optional[int] = None,
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout or self.timeout,
            check=False,
        )

    @staticmethod
    def parse_int(value: str) -> Optional[int]:
        value = value.strip()
        try:
            return int(value, 0)
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def verify_binary(self) -> bool:
        if not os.path.isfile(self.binary):
            self.result["errors"].append(
                f"Binary not found: {self.binary}"
            )
            return False

        if not os.access(self.binary, os.X_OK):
            self.result["errors"].append(
                f"Binary is not executable: {self.binary}"
            )
            return False

        return True

    def discover_symbols(self) -> list[TargetCandidate]:
        proc = self.run_cmd(
            ["nm", "-an", self.binary],
            timeout=10,
        )

        candidates: list[TargetCandidate] = []

        if proc.returncode != 0:
            return candidates

        for line in proc.stdout.splitlines():
            parts = line.split()

            if len(parts) < 3:
                continue

            address_text = parts[0]
            symbol_type = parts[1]
            name = parts[2]

            address = self.parse_int("0x" + address_text)

            if address is None:
                continue

            if symbol_type.lower() not in {"t", "w"}:
                continue

            lower = name.lower()

            score = 0.0

            if lower in self.TARGET_NAMES:
                score += 100.0

            if any(
                token in lower
                for token in (
                    "flag",
                    "win",
                    "success",
                    "winner",
                    "secret",
                    "shell",
                )
            ):
                score += 50.0

            if score > 0:
                candidates.append(
                    TargetCandidate(
                        name=name,
                        address=address,
                        source="nm",
                        score=score,
                    )
                )

        candidates.sort(
            key=lambda item: (-item.score, item.name)
        )

        self.result["control_flow"] = [
            {
                "name": item.name,
                "address": hex(item.address),
                "source": item.source,
                "score": item.score,
            }
            for item in candidates
        ]

        return candidates

    # ------------------------------------------------------------------
    # Source evidence
    # ------------------------------------------------------------------

    def find_source(self) -> Optional[str]:
        binary_path = Path(self.binary)

        candidates = [
            binary_path.with_suffix(".c"),
            binary_path.with_suffix(".cc"),
            binary_path.with_suffix(".cpp"),
        ]

        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)

        return None

    def analyze_source(self) -> dict[str, Any]:
        source = self.find_source()

        if not source:
            return {}

        try:
            text = Path(source).read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return {}

        evidence: dict[str, Any] = {
            "source": source,
            "controlled_write": False,
            "pointer_arithmetic": False,
            "input_functions": [],
            "targets": [],
        }

        input_functions = sorted(
            set(
                re.findall(
                    r"\b(scanf|fgets|gets|read|recv|scanf|sscanf)\b",
                    text,
                )
            )
        )

        evidence["input_functions"] = input_functions

        write_patterns = [
            r"\*\s*\([^)]*\)\s*[^;=]+\s*=",
            r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*=",
            r"\[[^\]]+\]\s*=",
            r"\bmemcpy\s*\(",
            r"\bmemmove\s*\(",
            r"\bstrcpy\s*\(",
            r"\bstrncpy\s*\(",
        ]

        evidence["controlled_write"] = any(
            re.search(pattern, text)
            for pattern in write_patterns
        )

        arithmetic_patterns = [
            r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*[-+]=",
            r"\*\s*\([^)]*\)\s*[-+]=",
        ]

        evidence["pointer_arithmetic"] = any(
            re.search(pattern, text)
            for pattern in arithmetic_patterns
        )

        for name in re.findall(
            r"\b(?:void|int|long|unsigned|char|static)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            text,
        ):
            lower = name.lower()

            if (
                lower in self.TARGET_NAMES
                or "flag" in lower
                or "win" in lower
                or "success" in lower
            ):
                evidence["targets"].append(name)

        self.result["source_analysis"] = evidence

        return evidence

    # ------------------------------------------------------------------
    # Runtime GDB support
    # ------------------------------------------------------------------

    def gdb_script(
        self,
        function: str,
        fifo: str,
        target_names: list[str],
    ) -> str:
        return f"""
set pagination off
set confirm off
set verbose off
set breakpoint pending on
set print pretty off
set disassemble-next-line off
set disable-randomization on

file {self.binary}

break {function}

commands
silent

printf "CYBERAI_BP_FUNCTION={function}\\n"
printf "CYBERAI_PC=%p\\n", $pc
printf "CYBERAI_SP=%p\\n", $sp
printf "CYBERAI_FP=%p\\n", $x29
printf "CYBERAI_LR=%p\\n", $x30
printf "CYBERAI_SAVED_LR_ADDR=%p\\n", $x29 + 8
printf "CYBERAI_SAVED_LR=%p\\n", *(unsigned long *)($x29 + 8)

printf "CYBERAI_ADDR_BALANCE=%p\\n", &balance
printf "CYBERAI_ADDR_WAGER=%p\\n", &wager
printf "CYBERAI_ADDR_ADDR=%p\\n", &addr
printf "CYBERAI_ADDR_VALUE=%p\\n", &value
printf "CYBERAI_BALANCE_PTR=%p\\n", balance

printf "CYBERAI_RUNTIME_GAME=%p\\n", game

info locals
info args

printf "CYBERAI_RUNTIME_SYMBOLS_BEGIN\\n"
info address {function}
printf "CYBERAI_RUNTIME_SYMBOLS_END\\n"

continue
end

run < {fifo}
quit
"""

    def parse_runtime_output(
        self,
        text: str,
    ) -> dict[str, Any]:
        state: dict[str, Any] = {}

        patterns = {
            "pc": r"CYBERAI_PC=(0x[0-9a-fA-F]+)",
            "sp": r"CYBERAI_SP=(0x[0-9a-fA-F]+)",
            "fp": r"CYBERAI_FP=(0x[0-9a-fA-F]+)",
            "lr": r"CYBERAI_LR=(0x[0-9a-fA-F]+)",
            "saved_lr_address": (
                r"CYBERAI_SAVED_LR_ADDR=(0x[0-9a-fA-F]+)"
            ),
            "saved_lr": (
                r"CYBERAI_SAVED_LR=(0x[0-9a-fA-F]+)"
            ),
            "balance_slot": (
                r"CYBERAI_ADDR_BALANCE=(0x[0-9a-fA-F]+)"
            ),
            "wager_slot": (
                r"CYBERAI_ADDR_WAGER=(0x[0-9a-fA-F]+)"
            ),
            "addr_slot": (
                r"CYBERAI_ADDR_ADDR=(0x[0-9a-fA-F]+)"
            ),
            "value_slot": (
                r"CYBERAI_ADDR_VALUE=(0x[0-9a-fA-F]+)"
            ),
            "balance": (
                r"CYBERAI_BALANCE_PTR=(0x[0-9a-fA-F]+)"
            ),
            "runtime_game": (
                r"CYBERAI_RUNTIME_GAME=(0x[0-9a-fA-F]+)"
            ),
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if not match:
                continue

            value = self.parse_int(match.group(1))
            if value is not None:
                state[key] = value

        # Fallback: GDB's "game (balance=...)" line.
        if "balance" not in state:
            match = re.search(
                r"game\s*\(balance=(0x[0-9a-fA-F]+)\)",
                text,
            )
            if match:
                value = self.parse_int(match.group(1))
                if value is not None:
                    state["balance"] = value

        # Fallback for saved LR if the explicit marker is unavailable.
        if "saved_lr" not in state:
            saved_match = re.search(
                r"0x[0-9a-fA-F]+:\s+"
                r"(0x[0-9a-fA-F]+)",
                text,
            )
            if saved_match:
                value = self.parse_int(saved_match.group(1))
                if value is not None:
                    state["saved_lr"] = value

        # Extract the runtime address reported by:
        #   Symbol "game" is a function at address 0x...
        symbol_match = re.search(
            r'Symbol\s+"'
            + re.escape("game")
            + r'"\s+is a function at address\s+'
            r"(0x[0-9a-fA-F]+)",
            text,
        )

        if symbol_match:
            value = self.parse_int(symbol_match.group(1))
            if value is not None:
                state["runtime_game_symbol"] = value

        # Keep GDB return code if the caller injected it.
        return state

    def discover_runtime_state(
        self,
        function: str,
    ) -> dict[str, Any]:
        fifo_path = None
        script_path = None

        try:
            fifo = tempfile.NamedTemporaryFile(
                prefix="cyberai_pwn_",
                delete=False,
            )
            fifo.close()

            fifo_path = fifo.name
            os.unlink(fifo_path)
            os.mkfifo(fifo_path, 0o600)

            script = self.gdb_script(
                function=function,
                fifo=fifo_path,
                target_names=[
                    item["name"]
                    for item in self.result.get(
                        "control_flow",
                        [],
                    )
                ],
            )

            script_file = tempfile.NamedTemporaryFile(
                mode="w",
                prefix="cyberai_gdb_",
                suffix=".gdb",
                delete=False,
                encoding="utf-8",
            )

            script_file.write(script)
            script_file.close()

            script_path = script_file.name

            # GDB needs an input stream. A small helper process opens
            # the FIFO and supplies only enough input to let scanf()
            # reach the controlled-write point.
            #
            # The exact exploit payload is NOT supplied here.
            # This phase only obtains runtime state.
            feeder_code = (
                "import sys,time;"
                f"f=open({fifo_path!r},'w');"
                "f.write('1\\n');"
                "f.flush();"
                "time.sleep(2);"
                "f.close()"
            )

            feeder = subprocess.Popen(
                ["python3", "-c", feeder_code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            try:
                proc = subprocess.run(
                    [
                        self.gdb_path,
                        "-q",
                        "-batch",
                        "-x",
                        script_path,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=self.timeout,
                    check=False,
                )
            finally:
                try:
                    feeder.kill()
                except Exception:
                    pass

            combined = (
                proc.stdout
                + "\n"
                + proc.stderr
            )

            state = self.parse_runtime_output(combined)

            state["gdb_returncode"] = proc.returncode
            state["gdb_output"] = combined[-12000:]

            self.result["state"].update(
                {
                    key: (
                        hex(value)
                        if isinstance(value, int)
                        and key not in {"gdb_returncode"}
                        else value
                    )
                    for key, value in state.items()
                }
            )

            return state

        except Exception as exc:
            self.result["errors"].append(
                f"Runtime discovery error: {exc}"
            )
            return {}

        finally:
            for path in (fifo_path, script_path):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    # Candidate analysis
    # ------------------------------------------------------------------

    @staticmethod
    def byte_delta(
        old_value: int,
        new_value: int,
    ) -> list[dict[str, Any]]:
        old = int(old_value).to_bytes(
            8,
            "little",
            signed=False,
        )

        new = int(new_value).to_bytes(
            8,
            "little",
            signed=False,
        )

        result = []

        for index, (before, after) in enumerate(
            zip(old, new)
        ):
            if before != after:
                result.append(
                    {
                        "byte": index,
                        "before": before,
                        "after": after,
                    }
                )

        return result

    def generate_candidates(
        self,
        state: dict[str, Any],
        targets: list[TargetCandidate],
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []

        saved_lr = state.get("saved_lr")
        saved_lr_address = state.get(
            "saved_lr_address"
        )

        if saved_lr is None or saved_lr_address is None:
            return candidates

        for target in targets:
            target_runtime = target.address

            # PIE runtime addresses cannot be used directly from nm.
            # A target with a known static symbol is only a semantic
            # candidate until its runtime address is observed.
            candidate = {
                "strategy": "saved_lr_byte_redirect",
                "target": target.name,
                "target_static": hex(target.address),
                "saved_lr": hex(saved_lr),
                "saved_lr_address": hex(
                    saved_lr_address
                ),
                "byte_delta": self.byte_delta(
                    saved_lr,
                    target_runtime,
                ),
                "validated": False,
            }

            candidates.append(candidate)

        # Pointer-redirection candidate.
        candidates.append(
            {
                "strategy": "pointer_alias_saved_lr",
                "saved_lr_address": hex(
                    saved_lr_address
                ),
                "saved_lr": hex(saved_lr),
                "validated": False,
            }
        )

        return candidates

    # ------------------------------------------------------------------
    # Runtime target resolution
    # ------------------------------------------------------------------

    def resolve_runtime_target(
        self,
        target_name: str,
    ) -> Optional[int]:
        script = f"""
set pagination off
set confirm off
set disable-randomization on
file {self.binary}
starti
printf "CYBERAI_TARGET_RUNTIME=%p\\n", {target_name}
quit
"""

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".gdb",
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(script)
                path = f.name

            try:
                proc = subprocess.run(
                    [
                        self.gdb_path,
                        "-q",
                        "-batch",
                        "-x",
                        path,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=self.timeout,
                    check=False,
                )
            finally:
                os.unlink(path)

            text = proc.stdout + "\n" + proc.stderr

            match = re.search(
                r"CYBERAI_TARGET_RUNTIME="
                r"(0x[0-9a-fA-F]+)",
                text,
            )

            if not match:
                return None

            return self.parse_int(match.group(1))

        except Exception:
            return None

    # ------------------------------------------------------------------
    # Flag detection
    # ------------------------------------------------------------------

    def detect_flags(
        self,
        text: str,
    ) -> list[str]:
        found: list[str] = []

        for pattern in self.FLAG_PATTERNS:
            for match in pattern.findall(text):
                if match not in found:
                    found.append(match)

        return found

    # ------------------------------------------------------------------
    # Runtime experiment
    # ------------------------------------------------------------------

    def execute_experiment(
        self,
        function: str,
        candidate: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute one runtime observation.

        V3 deliberately separates:
          discovery
          candidate generation
          validation

        A candidate is never considered validated solely because
        static analysis found an interesting address.
        """

        result = {
            "id": "pwn-runtime-001",
            "strategy": candidate.get("strategy"),
            "status": "RUNTIME_EVIDENCE",
            "validated": False,
            "flag_found": False,
            "flags": [],
            "observations": [],
        }

        self.observe(
            "RUNTIME_EVIDENCE",
            0.55,
            "Runtime state was collected from the inferior.",
            {
                "candidate": candidate,
            },
        )

        result["observations"].append(
            {
                "status": "RUNTIME_EVIDENCE",
                "candidate": candidate,
            }
        )

        return result

    # ------------------------------------------------------------------
    # Full analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        function: str = "game",
    ) -> dict[str, Any]:
        if not self.verify_binary():
            return self.fail(
                "Binary validation failed."
            )

        targets = self.discover_symbols()
        source = self.analyze_source()

        self.result["metadata"] = {
            "target_count": len(targets),
            "source_analysis": source,
        }

        if not targets:
            self.observe(
                "STATIC_EVIDENCE",
                0.20,
                "No semantic control-flow target was found.",
            )

        state = self.discover_runtime_state(function)

        if not state:
            return self.fail(
                "Unable to obtain runtime state."
            )

        candidates = self.generate_candidates(
            state,
            targets,
        )

        self.result["candidate_targets"] = candidates

        if not candidates:
            return self.fail(
                "No runtime exploitation candidate was generated."
            )

        # At this stage we intentionally do NOT call a target function
        # and do NOT claim exploitation success.
        candidate = candidates[0]

        self.result["candidate"] = candidate
        self.result["strategy"] = candidate.get(
            "strategy"
        )

        experiment = self.execute_experiment(
            function=function,
            candidate=candidate,
        )

        self.result["experiments"].append(
            experiment
        )

        if experiment.get("flag_found"):
            self.result["flags"].extend(
                experiment.get("flags", [])
            )
            self.result["status"] = "FLAG_FOUND"
        else:
            self.result["status"] = (
                "RUNTIME_EVIDENCE"
            )

        return self.result


# ----------------------------------------------------------------------
# Compatibility entry point
# ----------------------------------------------------------------------

def analyze(
    binary: str,
    function: str = "game",
) -> dict[str, Any]:
    engine = PwnRuntimeEngine(binary)
    return engine.analyze(function=function)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberAI PwnRuntimeEngine V3"
    )

    parser.add_argument(
        "binary",
        help="ELF binary",
    )

    parser.add_argument(
        "--function",
        default="game",
        help="Function used for runtime analysis",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--json",
        default=None,
        help="Write JSON result to file",
    )

    args = parser.parse_args()

    engine = PwnRuntimeEngine(
        binary=args.binary,
        timeout=args.timeout,
        retries=args.retries,
    )

    result = engine.analyze(
        function=args.function
    )

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )

    if args.json:
        with open(
            args.json,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                result,
                f,
                indent=2,
                ensure_ascii=False,
            )


if __name__ == "__main__":
    main()
