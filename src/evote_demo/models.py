from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import canonical_json, sha256_hex


@dataclass(frozen=True)
class Election:
    election_id: str
    choices: tuple[str, ...]

    def validate_choice(self, choice: str) -> None:
        if choice not in self.choices:
            raise ValueError(f"invalid choice: {choice}")


@dataclass(frozen=True)
class Credential:
    election_id: str
    ticket: str
    anon_public_key_pem: str

    def to_signable(self) -> bytes:
        return canonical_json(self)


@dataclass(frozen=True)
class VotePayload:
    credential: Credential
    auth_signature: str
    nonce: str
    encrypted_vote: str
    anon_signature: str

    def anon_signable(self) -> bytes:
        return canonical_json(
            {
                "credential": self.credential,
                "auth_signature": self.auth_signature,
                "nonce": self.nonce,
                "encrypted_vote": self.encrypted_vote,
            }
        )


@dataclass(frozen=True)
class VotePoolItem:
    payload: VotePayload
    vote_server_signature: str

    def vote_server_signable(self) -> bytes:
        return canonical_json(self.payload)


@dataclass(frozen=True)
class VoteTransaction:
    ticket: str
    encrypted_vote: str
    status: str = "accepted"

    @property
    def tx_hash(self) -> str:
        return sha256_hex(canonical_json(self))


@dataclass(frozen=True)
class BlockHeader:
    index: int
    election_id: str
    previous_hash: str
    timestamp: str
    tx_count: int
    merkle_root: str
    proposer_id: str


@dataclass
class Block:
    header: BlockHeader
    transactions: list[VoteTransaction]
    block_hash: str
    proposer_signature: str
    acceptor_signatures: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MerkleProofStep:
    sibling_hash: str
    sibling_position: str


@dataclass(frozen=True)
class Receipt:
    election_id: str
    block_index: int
    tx_hash: str
    merkle_proof: tuple[MerkleProofStep, ...]
    notifier_signature: str

    def signable(self) -> bytes:
        return canonical_json(
            {
                "election_id": self.election_id,
                "block_index": self.block_index,
                "tx_hash": self.tx_hash,
                "merkle_proof": self.merkle_proof,
            }
        )

