from __future__ import annotations

import argparse

from common import build_system, measure_prepared, positive_int, print_measurements, submit_votes


def prepare_credential_issue():
    """Prepara lo stato per misurare il rilascio della credenziale."""

    from evote_demo.services import VoterClient

    _election, auth, _scrutiny, _voting, _pool, _blockchain, _network = build_system(voters=1, block_size=4)
    client = VoterClient("VR001")
    return auth, client


def prepare_build_vote():
    """Prepara lo stato per misurare la costruzione del voto."""

    from evote_demo.services import VoterClient

    election, auth, scrutiny, _voting, _pool, _blockchain, _network = build_system(voters=1, block_size=4)
    client = VoterClient("VR001")
    credential, auth_signature = auth.issue_credential("VR001", client.anon_public_key_pem)
    return election, scrutiny, client, credential, auth_signature


def prepare_receive_vote():
    """Prepara lo stato per misurare l'invio al server di voto."""

    from evote_demo.services import VoterClient

    election, auth, scrutiny, voting, pool, _blockchain, _network = build_system(voters=1, block_size=4)
    client = VoterClient("VR001")
    credential, auth_signature = auth.issue_credential("VR001", client.anon_public_key_pem)
    payload = client.build_vote(election, scrutiny.public_key_pem, "Lista A", credential, auth_signature)
    return voting, pool, payload


def prepare_process_pool(voters: int, block_size: int):
    """Prepara voti in pool senza processarli."""

    return submit_votes(voters=voters, block_size=block_size, process=False)


def prepare_processed(voters: int, block_size: int):
    """Prepara uno scenario gia processato dai validatori."""

    return submit_votes(voters=voters, block_size=block_size, process=True)


def run(samples: int = 20, voters: int = 5, block_size: int = 4) -> None:
    """Misura le latenze delle interazioni principali della demo."""

    measurements = [
        measure_prepared(
            "Interazione: rilascio credenziale",
            prepare_credential_issue,
            lambda state: state[0].issue_credential("VR001", state[1].anon_public_key_pem),
            samples,
        ),
        measure_prepared(
            "Interazione: preparazione scheda",
            prepare_build_vote,
            lambda state: state[2].build_vote(
                state[0],
                state[1].public_key_pem,
                "Lista A",
                credential=state[3],
                auth_signature=state[4],
            ),
            samples,
        ),
        measure_prepared(
            "Interazione: invio al server voto",
            prepare_receive_vote,
            lambda state: state[0].receive_vote(state[2], state[1]),
            samples,
        ),
        measure_prepared(
            "Validazione: avanzamento validatori",
            lambda: prepare_process_pool(voters, block_size),
            lambda state: state[6].process_pool(state[4], flush=True),
            samples,
        ),
        measure_prepared(
            "Verifica: ricevuta individuale",
            lambda: prepare_processed(voters, block_size),
            lambda state: state[5].verify_receipt(
                state[1].get_receipt("VR001"),
                state[6].notifier.public_key_pem,
            ),
            samples,
        ),
        measure_prepared(
            "Scrutinio: conteggio finale",
            lambda: prepare_processed(voters, block_size),
            lambda state: state[2].tally(state[5]),
            samples,
        ),
    ]
    print_measurements("Latenza delle verifiche e tempi di interazione", measurements)
    print(f"\nScenario: {voters} voti, blocchi da {block_size}, 5 validatori, consenso 3 su 5.")


def main() -> None:
    """Legge gli argomenti CLI e avvia il benchmark di latenza."""

    parser = argparse.ArgumentParser(description="Misura latenze locali delle verifiche e delle interazioni.")
    parser.add_argument("--samples", type=positive_int, default=20, help="Numero di misurazioni per operazione.")
    parser.add_argument("--voters", type=positive_int, default=5, help="Numero di voti simulati.")
    args = parser.parse_args()
    run(args.samples, args.voters)


if __name__ == "__main__":
    main()
