from __future__ import annotations

from common import print_table, submit_votes

from evote_demo.crypto import canonical_json


def byte_len(value: object) -> int:
    """Calcola quanti byte occupa un valore nel JSON canonico."""

    return len(canonical_json(value))


def run() -> None:
    """Stampa dimensioni dei messaggi e grandezze strutturali."""

    _election, auth, _scrutiny, _voting, _pool, _blockchain, network, artifacts, blocks = submit_votes(
        voters=5,
        block_size=4,
        process=True,
    )
    _client, credential, auth_signature, payload, item = artifacts[0]
    block = blocks[0]
    tx = block.transactions[0]
    receipt = auth.get_receipt("VR001")
    if receipt is None:
        raise RuntimeError("receipt was not generated")

    rows = [
        ("Credenziale anonima", byte_len(credential), "ticket + chiave pubblica anonima PEM"),
        ("Firma server autenticazione", len(auth_signature.encode("ascii")), "firma RSA-2048 in base64"),
        ("Payload voto cifrato", byte_len(payload), "credenziale + nonce + voto cifrato + firme"),
        ("Item Vote Pool", byte_len(item), "payload + firma server voto"),
        ("Transazione nel blocco", byte_len(tx), "ticket + voto cifrato + stato"),
        ("Blocco", byte_len(block), "header + transazioni + firme validatori"),
        ("Ricevuta", byte_len(receipt), "tx_hash + Merkle proof + firma notificatore"),
        ("Merkle proof", byte_len(receipt.merkle_proof), f"{len(receipt.merkle_proof)} passi"),
        ("Firma notificatore", len(receipt.notifier_signature.encode("ascii")), "firma RSA-2048 in base64"),
        ("Chiave pubblica validatore", len(network.notifier.public_key_pem.encode("ascii")), "PEM SubjectPublicKeyInfo"),
    ]

    print("\nDimensione dei messaggi scambiati")
    print("--------------------------------")
    print_table(("Messaggio/Dato", "Byte", "Contenuto principale"), [(n, str(s), note) for n, s, note in rows])

    print("\nGrandezze strutturali")
    print("---------------------")
    print_table(
        ("Grandezza", "Valore"),
        [
            ("Lunghezza hash SHA-256 esadecimale", "64 caratteri"),
            ("Lunghezza firma RSA-2048 grezza", "256 byte"),
            ("Lunghezza firma/ciphertext RSA-2048 base64", f"{len(payload.encrypted_vote)} caratteri"),
            ("Passi Merkle proof nel blocco corrente", str(len(receipt.merkle_proof))),
        ],
    )


def main() -> None:
    """Avvia la stampa delle dimensioni dei messaggi."""

    run()


if __name__ == "__main__":
    main()
