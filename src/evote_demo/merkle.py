from __future__ import annotations

import hashlib

from .models import MerkleProofStep, VoteTransaction


EMPTY_LEAF = ""


def sha256(data: str) -> str:
    """Calcola SHA-256 su una stringa e restituisce l'hash esadecimale."""

    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_merkle_tree(data_list: list[str]) -> tuple[str, list[list[str]]]:
    """Costruisce l'albero di Merkle e restituisce root e livelli."""

    if not data_list:
        raise ValueError("data_list must not be empty")

    tree = [[sha256(data) for data in data_list]]

    while len(tree[-1]) > 1:
        level = tree[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        tree.append([sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)])

    return tree[-1][0], tree


def generate_proof(leaf_index: int, tree: list[list[str]]) -> list[tuple[str, str]]:
    """Crea il percorso di verifica per una foglia dell'albero."""

    proof: list[tuple[str, str]] = []
    index = leaf_index

    for level in tree[:-1]:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        sibling_index = index ^ 1
        position = "right" if sibling_index > index else "left"
        proof.append((position, level[sibling_index]))
        index //= 2

    return proof


def verify_proof(data: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Verifica che un dato appartenga alla Merkle root indicata."""

    current = sha256(data)

    for position, sibling in proof:
        if position == "right":
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)

    return current == root


def transaction_leaves(transactions: list[VoteTransaction], block_size: int) -> list[str]:
    """Trasforma le transazioni in foglie, riempiendo il blocco se serve."""

    leaves = [tx.tx_hash for tx in transactions]
    while len(leaves) < block_size:
        leaves.append(EMPTY_LEAF)
    return leaves


def merkle_root(transactions: list[VoteTransaction], block_size: int) -> str:
    """Calcola la Merkle root delle transazioni di un blocco."""

    root, _tree = build_merkle_tree(transaction_leaves(transactions, block_size))
    return root


def merkle_proof(transactions: list[VoteTransaction], block_size: int, tx_hash: str) -> tuple[MerkleProofStep, ...]:
    """Genera la prova Merkle per una transazione presente nel blocco."""

    leaves = transaction_leaves(transactions, block_size)
    try:
        index = leaves.index(tx_hash)
    except ValueError as exc:
        raise ValueError("transaction is not in this block") from exc

    _root, tree = build_merkle_tree(leaves)
    return tuple(MerkleProofStep(sibling_hash, sibling_position) for sibling_position, sibling_hash in generate_proof(index, tree))


def verify_merkle_proof(tx_hash: str, proof: tuple[MerkleProofStep, ...], expected_root: str) -> bool:
    """Controlla una prova Merkle usando il formato dati della demo."""

    return verify_proof(
        tx_hash,
        [(step.sibling_position, step.sibling_hash) for step in proof],
        expected_root,
    )
