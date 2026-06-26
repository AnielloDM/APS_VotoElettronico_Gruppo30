from __future__ import annotations

import argparse

from common import positive_int
from crypto_costs import run as run_crypto_costs
from message_sizes import run as run_message_sizes
from verification_latency import run as run_verification_latency


def main() -> None:
    """Esegue in sequenza tutti i benchmark disponibili."""

    parser = argparse.ArgumentParser(description="Esegue tutti gli esperimenti prestazionali della demo.")
    parser.add_argument("--samples", type=positive_int, default=20, help="Numero di misurazioni per benchmark.")
    parser.add_argument("--voters", type=positive_int, default=5, help="Numero di voti nello scenario di latenza.")
    args = parser.parse_args()

    run_crypto_costs(args.samples)
    run_message_sizes()
    run_verification_latency(args.samples, args.voters)


if __name__ == "__main__":
    main()
