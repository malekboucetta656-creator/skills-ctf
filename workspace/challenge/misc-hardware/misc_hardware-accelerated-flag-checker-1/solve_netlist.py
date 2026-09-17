#!/usr/bin/env python3

import re
from collections import deque

NETLIST = "netlist.v"

# ------------------------------------------------------------
# Lecture des assign
# ------------------------------------------------------------

text = open(NETLIST, encoding="utf-8").read()

assigns = {}

for lhs, rhs in re.findall(
    r"^\s*assign\s+([^\s=]+)\s*=\s*(.*?);\s*$",
    text,
    re.M
):
    assigns[lhs] = rhs.strip()

print(f"[+] Equations: {len(assigns)}")

# ------------------------------------------------------------
# Tokenizer
# ------------------------------------------------------------

TOKEN_RE = re.compile(
    r"_\d+_\[\d+\]"
    r"|character\[\d+\]"
    r"|s\[\d\]"
    r"|[A-Za-z_][A-Za-z0-9_]*"
    r"|[~&|()]"
)

def tokenize(expr):
    tokens = TOKEN_RE.findall(expr)

    # Vérification stricte :
    compact = re.sub(r"\s+", "", expr)
    rebuilt = "".join(tokens)

    if rebuilt != compact:
        raise ValueError(
            f"Tokenization incomplete: {expr!r} -> {tokens!r}"
        )

    return tokens


# ------------------------------------------------------------
# Evaluateur
# ------------------------------------------------------------

def make_evaluator(state, char):

    env = {}

    for i in range(5):
        env[f"s[{i}]"] = (state >> i) & 1

    for i in range(7):
        env[f"character[{i}]"] = (char >> i) & 1

    cache = {}
    active = set()

    def signal(name):

        if name in env:
            return env[name]

        if name in cache:
            return cache[name]

        if name not in assigns:
            raise KeyError(
                f"Unknown signal {name!r}"
            )

        if name in active:
            raise RuntimeError(
                f"Combinational loop involving {name}"
            )

        active.add(name)

        try:
            value = parse_expression(assigns[name])
            value &= 1
            cache[name] = value
            return value

        finally:
            active.remove(name)

    def parse_expression(expr):

        tokens = tokenize(expr)
        pos = 0

        def peek():
            if pos >= len(tokens):
                return None
            return tokens[pos]

        def consume(expected=None):

            nonlocal pos

            if pos >= len(tokens):
                raise ValueError(
                    f"Unexpected end of expression: {expr}"
                )

            token = tokens[pos]

            if expected is not None and token != expected:
                raise ValueError(
                    f"Expected {expected!r}, got {token!r} "
                    f"in {expr!r}"
                )

            pos += 1
            return token

        # ~
        def parse_not():

            if peek() == "~":
                consume("~")
                return 1 ^ parse_not()

            return parse_primary()

        # ()
        def parse_primary():

            token = peek()

            if token is None:
                raise ValueError(
                    f"Unexpected end: {expr!r}"
                )

            if token == "(":

                consume("(")
                value = parse_or()
                consume(")")

                return value

            if token in ("&", "|", ")"):
                raise ValueError(
                    f"Unexpected token {token!r} "
                    f"in {expr!r}"
                )

            consume()

            return signal(token)

        # &
        def parse_and():

            value = parse_not()

            while peek() == "&":

                consume("&")

                right = parse_not()

                value &= right

            return value & 1

        # |
        def parse_or():

            value = parse_and()

            while peek() == "|":

                consume("|")

                right = parse_and()

                value |= right

            return value & 1

        result = parse_or()

        if pos != len(tokens):
            raise ValueError(
                f"Remaining tokens {tokens[pos:]} "
                f"in {expr!r}"
            )

        return result & 1

    return signal


# ------------------------------------------------------------
# Evaluation d'une transition FSM
# ------------------------------------------------------------

def evaluate(state, char):

    signal = make_evaluator(state, char)

    next_state = 0

    for bit in range(5):

        name = f"_289_[{bit}]"

        value = signal(name)

        next_state |= (value & 1) << bit

    # Le flag devient actif lorsque le registre
    # d'état atteint 11111 après le front d'horloge.
    found = (next_state == 31)

    return next_state, found


# ------------------------------------------------------------
# Construction FSM
# ------------------------------------------------------------

print("[+] Building FSM...")

transitions = {}

for state in range(32):

    if state % 4 == 0:
        print(f"    state {state}/31")

    for char in range(128):

        try:

            transitions[(state, char)] = evaluate(
                state,
                char
            )

        except Exception as e:

            print()
            print(
                f"[!] evaluation error "
                f"state={state} "
                f"char={char} "
                f"({char:#04x})"
            )
            print(f"    {e}")

            # Afficher l'expression problématique
            print()

            raise


print("[+] FSM built successfully")


# ------------------------------------------------------------
# BFS
# ------------------------------------------------------------

print("[+] Searching reachable states...")

START = 0

queue = deque([
    (START, b"")
])

# state -> chemin le plus court
visited = {
    START: b""
}

solutions = []

MAX_LEN = 64

while queue:

    state, prefix = queue.popleft()

    for char in range(128):

        ns, found = transitions[(state, char)]

        new_prefix = prefix + bytes([char])

        if found:

            solutions.append(new_prefix)

            print()
            print("[FOUND]")
            print(f"  length : {len(new_prefix)}")
            print(f"  bytes  : {new_prefix!r}")

            try:
                print(f"  text   : {new_prefix.decode('ascii')}")

            except UnicodeDecodeError:
                print(
                    f"  hex    : "
                    f"{new_prefix.hex()}"
                )

            continue

        if ns not in visited and len(new_prefix) < MAX_LEN:

            visited[ns] = new_prefix

            queue.append(
                (ns, new_prefix)
            )


# ------------------------------------------------------------
# Résultats
# ------------------------------------------------------------

print()
print("========================================")
print("           FSM ANALYSIS")
print("========================================")

print(
    f"Reachable states : "
    f"{len(visited)}/32"
)

print(
    f"Solutions        : "
    f"{len(solutions)}"
)

print()

print("===== REACHABLE STATES =====")

for state in sorted(visited):

    path = visited[state]

    printable = ""

    try:
        printable = path.decode("ascii")
    except UnicodeDecodeError:
        printable = path.hex()

    print(
        f"  {state:02d} "
        f"{state:05b} : "
        f"{printable!r}"
    )


if solutions:

    print()
    print("===== CANDIDATES =====")

    for candidate in solutions:

        print()
        print(repr(candidate))

        try:
            print(candidate.decode("ascii"))

        except UnicodeDecodeError:
            print(candidate.hex())

else:

    print()
    print(
        "[!] Aucun chemin vers "
        "l'état 11111 trouvé."
    )
