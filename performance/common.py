from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence, TypeVar


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


T = TypeVar("T")


@dataclass(frozen=True)
class Measurement:
    """Risultato sintetico di una misurazione ripetuta."""

    name: str
    samples: int
    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float


def positive_int(value: str) -> int:
    """Converte un argomento CLI in intero positivo."""

    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def measure(name: str, operation: Callable[[], object], samples: int, warmups: int = 3) -> Measurement:
    """Misura il tempo di una operazione gia pronta da eseguire."""

    for _ in range(warmups):
        operation()

    durations: list[float] = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()
        durations.append((end - start) / 1_000_000)

    return Measurement(
        name=name,
        samples=samples,
        mean_ms=statistics.fmean(durations),
        median_ms=statistics.median(durations),
        min_ms=min(durations),
        max_ms=max(durations),
    )


def measure_prepared(
    name: str,
    prepare: Callable[[], T],
    operation: Callable[[T], object],
    samples: int,
    warmups: int = 3,
) -> Measurement:
    """Misura una operazione ricreando lo stato prima di ogni prova."""

    for _ in range(warmups):
        operation(prepare())

    durations: list[float] = []
    for _ in range(samples):
        state = prepare()
        start = time.perf_counter_ns()
        operation(state)
        end = time.perf_counter_ns()
        durations.append((end - start) / 1_000_000)

    return Measurement(
        name=name,
        samples=samples,
        mean_ms=statistics.fmean(durations),
        median_ms=statistics.median(durations),
        min_ms=min(durations),
        max_ms=max(durations),
    )


def print_measurements(title: str, measurements: Sequence[Measurement]) -> None:
    """Stampa una lista di misure come tabella leggibile."""

    print(f"\n{title}")
    print("-" * len(title))
    headers = ("Operazione", "N", "Media ms", "Mediana ms", "Min ms", "Max ms")
    rows = [
        (
            item.name,
            str(item.samples),
            f"{item.mean_ms:.4f}",
            f"{item.median_ms:.4f}",
            f"{item.min_ms:.4f}",
            f"{item.max_ms:.4f}",
        )
        for item in measurements
    ]
    print_table(headers, rows)


def print_table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    """Stampa righe testuali allineate in colonne."""

    materialized = [tuple(row) for row in rows]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in materialized))
        for index in range(len(headers))
    ]
    header_line = "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers)))
    separator = "  ".join("-" * width for width in widths)
    print(header_line)
    print(separator)
    for row in materialized:
        print("  ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


def voter_id(index: int) -> str:
    """Genera un identificativo elettore nel formato della demo."""

    return f"VR{index:03d}"


def build_system(voters: int = 5, block_size: int = 4):
    """Crea un sistema di voto parametrico per i benchmark."""

    from evote_demo.models import Election
    from evote_demo.services import (
        AuthenticationServer,
        Blockchain,
        ScrutinyAuthority,
        Validator,
        ValidatorNetwork,
        VotePool,
        VotingServer,
    )

    election = Election("ElezionePerf", ("Lista A", "Lista B", "Lista C"))
    auth = AuthenticationServer(election, {voter_id(index) for index in range(1, voters + 1)})
    scrutiny = ScrutinyAuthority(election)
    voting = VotingServer(auth.public_key_pem)
    pool = VotePool()
    blockchain = Blockchain(election.election_id, block_size=block_size)
    validators = [Validator(f"validator-{index}") for index in range(1, 6)]
    network = ValidatorNetwork(validators, auth, voting, blockchain)
    return election, auth, scrutiny, voting, pool, blockchain, network


def submit_votes(voters: int = 5, block_size: int = 4, process: bool = True):
    """Simula invio dei voti e, se richiesto, anche la validazione."""

    from evote_demo.services import VoterClient

    election, auth, scrutiny, voting, pool, blockchain, network = build_system(voters, block_size)
    choices = ("Lista A", "Lista B", "Lista C")
    artifacts = []
    for index in range(1, voters + 1):
        client = VoterClient(voter_id(index))
        credential, auth_signature = auth.issue_credential(client.voter_id, client.anon_public_key_pem)
        payload = client.build_vote(
            election,
            scrutiny.public_key_pem,
            choices[(index - 1) % len(choices)],
            credential=credential,
            auth_signature=auth_signature,
        )
        item = voting.receive_vote(payload, pool)
        artifacts.append((client, credential, auth_signature, payload, item))

    blocks = network.process_pool(pool, flush=True) if process else []
    return election, auth, scrutiny, voting, pool, blockchain, network, artifacts, blocks
