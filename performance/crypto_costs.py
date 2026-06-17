from __future__ import annotations

import argparse

from common import measure, positive_int, print_measurements, submit_votes

from evote_demo.crypto import decrypt_with, encrypt_for, sha256_hex, sign, verify
from evote_demo.merkle import merkle_proof, merkle_root, verify_merkle_proof


def run(samples: int = 50) -> None:
    _election, auth, scrutiny, _voting, _pool, blockchain, _network, artifacts, blocks = submit_votes(
        voters=8,
        block_size=8,
        process=True,
    )
    _client, credential, auth_signature, payload, _item = artifacts[0]
    block = blocks[0]
    tx = block.transactions[0]
    proof = merkle_proof(block.transactions, blockchain.block_size, tx.tx_hash)
    message = credential.to_signable()
    ciphertext = payload.encrypted_vote

    measurements = [
        measure("SHA-256 su payload voto", lambda: sha256_hex(payload.anon_signable()), samples),
        measure("Firma RSA-PSS credenziale", lambda: sign(auth.keys.private_key, message), samples),
        measure(
            "Verifica firma RSA-PSS credenziale",
            lambda: verify(auth.keys.public_key, message, auth_signature),
            samples,
        ),
        measure(
            "Cifratura RSA-OAEP voto",
            lambda: encrypt_for(scrutiny.keys.public_key, b"Lista A"),
            samples,
        ),
        measure(
            "Decifratura RSA-OAEP voto",
            lambda: decrypt_with(scrutiny.keys.private_key, ciphertext),
            samples,
        ),
        measure(
            "Costruzione Merkle root blocco",
            lambda: merkle_root(block.transactions, blockchain.block_size),
            samples,
        ),
        measure(
            "Generazione Merkle proof",
            lambda: merkle_proof(block.transactions, blockchain.block_size, tx.tx_hash),
            samples,
        ),
        measure(
            "Verifica Merkle proof",
            lambda: verify_merkle_proof(tx.tx_hash, proof, block.header.merkle_root),
            samples,
        ),
    ]
    print_measurements("Costo computazionale delle operazioni crittografiche", measurements)


def main() -> None:
    parser = argparse.ArgumentParser(description="Misura il costo locale delle operazioni crittografiche.")
    parser.add_argument("--samples", type=positive_int, default=50, help="Numero di misurazioni per operazione.")
    args = parser.parse_args()
    run(args.samples)


if __name__ == "__main__":
    main()
