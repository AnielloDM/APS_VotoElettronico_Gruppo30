from __future__ import annotations

import secrets
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature

from .crypto import (
    canonical_json,
    decrypt_with,
    encrypt_for,
    generate_rsa_keypair,
    public_key_from_pem,
    public_key_to_pem,
    sha256_hex,
    sign,
    verify,
)
from .merkle import merkle_proof, merkle_root, verify_merkle_proof
from .models import (
    Block,
    BlockHeader,
    Credential,
    Election,
    Receipt,
    VotePayload,
    VotePoolItem,
    VoteTransaction,
)


class AuthenticationServer:
    def __init__(self, election: Election, eligible_voters: set[str]) -> None:
        self.election = election
        self.keys = generate_rsa_keypair()
        self._eligible_voters = eligible_voters
        self._records: dict[str, dict[str, object]] = {}
        self._ticket_owner: dict[str, str] = {}

    @property
    def public_key_pem(self) -> str:
        return public_key_to_pem(self.keys.public_key)

    def inspect_credential_request(self, voter_id: str) -> list["CheckResult"]:
        has_receipt = "receipt" in self._records.get(voter_id, {})
        return [
            CheckResult(
                "Elettore autorizzato",
                voter_id in self._eligible_voters,
                "la tessera compare tra gli aventi diritto",
            ),
            CheckResult(
                "Voto gia finalizzato",
                not has_receipt,
                "non esiste gia una ricevuta accettata per questo elettore",
            ),
        ]

    def issue_credential(self, voter_id: str, anon_public_key_pem: str) -> tuple[Credential, str]:
        if voter_id not in self._eligible_voters:
            raise PermissionError("voter is not eligible for this election")
        record = self._records.setdefault(voter_id, {})
        if "receipt" in record:
            raise PermissionError("this voter already has an accepted vote")
        ticket = str(record.get("ticket") or secrets.token_urlsafe(32))
        record["ticket"] = ticket
        self._ticket_owner[ticket] = voter_id
        credential = Credential(self.election.election_id, ticket, anon_public_key_pem)
        return credential, sign(self.keys.private_key, credential.to_signable())

    def store_receipt(self, ticket: str, receipt: Receipt) -> None:
        voter_id = self._ticket_owner.get(ticket)
        if voter_id is None:
            raise KeyError("unknown ticket")
        self._records.setdefault(voter_id, {})["receipt"] = receipt

    def reissue_ticket_for_rejected_vote(self, ticket: str) -> tuple[str, str] | None:
        voter_id = self._ticket_owner.get(ticket)
        if voter_id is None:
            return None
        record = self._records.setdefault(voter_id, {})
        if record.get("receipt") is not None:
            return None
        if record.get("ticket") != ticket:
            return None
        new_ticket = secrets.token_urlsafe(32)
        record["ticket"] = new_ticket
        del self._ticket_owner[ticket]
        self._ticket_owner[new_ticket] = voter_id
        return voter_id, new_ticket

    def get_receipt(self, voter_id: str) -> Receipt | None:
        receipt = self._records.get(voter_id, {}).get("receipt")
        return receipt if isinstance(receipt, Receipt) else None


class VoterClient:
    def __init__(self, voter_id: str) -> None:
        self.voter_id = voter_id
        self.anon_keys = generate_rsa_keypair()

    @property
    def anon_public_key_pem(self) -> str:
        return public_key_to_pem(self.anon_keys.public_key)

    def build_vote(
        self,
        election: Election,
        scrutiny_public_key_pem: str,
        choice: str,
        credential: Credential | None = None,
        auth_signature: str = "",
    ) -> VotePayload:
        election.validate_choice(choice)
        if credential is None:
            credential = Credential(
                election_id=election.election_id,
                ticket="",
                anon_public_key_pem=self.anon_public_key_pem,
            )
        if credential.election_id != election.election_id:
            raise ValueError("credential refers to a different election")
        encrypted_vote = encrypt_for(public_key_from_pem(scrutiny_public_key_pem), choice.encode("utf-8"))
        nonce = secrets.token_urlsafe(18)
        unsigned = VotePayload(
            credential=credential,
            auth_signature=auth_signature,
            nonce=nonce,
            encrypted_vote=encrypted_vote,
            anon_signature="",
        )
        anon_signature = sign(self.anon_keys.private_key, unsigned.anon_signable())
        return VotePayload(credential, auth_signature, nonce, encrypted_vote, anon_signature)

class VotingServer:
    def __init__(self, auth_public_key_pem: str) -> None:
        self.keys = generate_rsa_keypair()
        self.auth_public_key = public_key_from_pem(auth_public_key_pem)
        self.used_nonces: set[str] = set()
        self.used_tickets: set[str] = set()

    @property
    def public_key_pem(self) -> str:
        return public_key_to_pem(self.keys.public_key)

    def inspect_payload(self, payload: VotePayload) -> list["CheckResult"]:
        auth_signature_ok = verify(self.auth_public_key, payload.credential.to_signable(), payload.auth_signature)
        anon_public_key = public_key_from_pem(payload.credential.anon_public_key_pem)
        anon_signature_ok = verify(anon_public_key, payload.anon_signable(), payload.anon_signature)
        return [
            CheckResult("Nonce nuovo", payload.nonce not in self.used_nonces, "previene replay del messaggio"),
            CheckResult(
                "Firma del server di autenticazione",
                auth_signature_ok,
                "la credenziale e firmata dal server di autenticazione",
            ),
            CheckResult(
                "Firma anonima dell'elettore",
                anon_signature_ok,
                "il voto e firmato con la chiave anonima legata alla credenziale",
            ),
            CheckResult(
                "Ticket non riutilizzato",
                payload.credential.ticket not in self.used_tickets,
                "lo stesso ticket non e gia stato usato presso il server di voto",
            ),
        ]

    def receive_vote(self, payload: VotePayload, vote_pool: "VotePool") -> VotePoolItem:
        self._validate_payload(payload)
        ticket = payload.credential.ticket
        if ticket in self.used_tickets:
            raise ValueError("ticket already used")
        self.used_nonces.add(payload.nonce)
        self.used_tickets.add(ticket)
        item = VotePoolItem(payload, sign(self.keys.private_key, canonical_json(payload)))
        vote_pool.push(item)
        return item

    def forward_vote_unchecked(self, payload: VotePayload, vote_pool: "VotePool") -> VotePoolItem:
        item = VotePoolItem(payload, sign(self.keys.private_key, canonical_json(payload)))
        vote_pool.push(item)
        return item

    def _validate_payload(self, payload: VotePayload) -> None:
        if payload.nonce in self.used_nonces:
            raise ValueError("replayed nonce")
        if not verify(self.auth_public_key, payload.credential.to_signable(), payload.auth_signature):
            raise InvalidSignature("invalid authentication-server signature")
        anon_public_key = public_key_from_pem(payload.credential.anon_public_key_pem)
        if not verify(anon_public_key, payload.anon_signable(), payload.anon_signature):
            raise InvalidSignature("invalid anonymous voter signature")


class VotePool:
    def __init__(self) -> None:
        self._items: list[VotePoolItem] = []

    def push(self, item: VotePoolItem) -> None:
        self._items.append(item)

    def pop_batch(self, size: int) -> list[VotePoolItem]:
        batch = self._items[:size]
        del self._items[:size]
        return batch

    def __len__(self) -> int:
        return len(self._items)


class Blockchain:
    def __init__(self, election_id: str, block_size: int = 4) -> None:
        self.election_id = election_id
        self.block_size = block_size
        self.blocks: list[Block] = []

    @property
    def last_hash(self) -> str:
        return self.blocks[-1].block_hash if self.blocks else "0" * 64

    def contains_ticket(self, ticket: str) -> bool:
        return any(tx.ticket == ticket for block in self.blocks for tx in block.transactions)

    def append(self, block: Block) -> None:
        if block.header.previous_hash != self.last_hash:
            raise ValueError("block does not point to current chain head")
        self.blocks.append(block)

    def find_transaction(self, tx_hash: str) -> tuple[Block, VoteTransaction] | None:
        for block in self.blocks:
            for tx in block.transactions:
                if tx.tx_hash == tx_hash:
                    return block, tx
        return None

    def verify_receipt(self, receipt: Receipt, notifier_public_key_pem: str) -> bool:
        if not verify(public_key_from_pem(notifier_public_key_pem), receipt.signable(), receipt.notifier_signature):
            return False
        if receipt.block_index >= len(self.blocks):
            return False
        block = self.blocks[receipt.block_index]
        if block.header.election_id != receipt.election_id:
            return False
        return verify_merkle_proof(receipt.tx_hash, receipt.merkle_proof, block.header.merkle_root)


@dataclass
class Validator:
    validator_id: str

    def __post_init__(self) -> None:
        self.keys = generate_rsa_keypair()

    @property
    def public_key_pem(self) -> str:
        return public_key_to_pem(self.keys.public_key)

    def inspect_item(
        self,
        item: VotePoolItem,
        auth_public_key_pem: str,
        vote_server_public_key_pem: str,
        blockchain: Blockchain,
    ) -> list["CheckResult"]:
        payload = item.payload
        auth_signature_ok = verify(public_key_from_pem(auth_public_key_pem), payload.credential.to_signable(), payload.auth_signature)
        anon_public_key = public_key_from_pem(payload.credential.anon_public_key_pem)
        anon_signature_ok = verify(anon_public_key, payload.anon_signable(), payload.anon_signature)
        vote_server_signature_ok = verify(
            public_key_from_pem(vote_server_public_key_pem),
            canonical_json(payload),
            item.vote_server_signature,
        )
        return [
            CheckResult(
                "Ticket assente dalla blockchain",
                not blockchain.contains_ticket(payload.credential.ticket),
                "nessun blocco precedente contiene gia questo ticket",
            ),
            CheckResult(
                "Firma della credenziale",
                auth_signature_ok,
                "i validatori confermano la firma del server di autenticazione",
            ),
            CheckResult(
                "Firma anonima",
                anon_signature_ok,
                "i validatori confermano il legame tra credenziale e voto",
            ),
            CheckResult(
                "Firma del server di voto",
                vote_server_signature_ok,
                "il payload e stato preso in carico dal server di voto",
            ),
        ]

    def validate_item(
        self,
        item: VotePoolItem,
        auth_public_key_pem: str,
        vote_server_public_key_pem: str,
        blockchain: Blockchain,
    ) -> bool:
        payload = item.payload
        if blockchain.contains_ticket(payload.credential.ticket):
            return False
        if not verify(public_key_from_pem(auth_public_key_pem), payload.credential.to_signable(), payload.auth_signature):
            return False
        anon_public_key = public_key_from_pem(payload.credential.anon_public_key_pem)
        if not verify(anon_public_key, payload.anon_signable(), payload.anon_signature):
            return False
        return verify(public_key_from_pem(vote_server_public_key_pem), canonical_json(payload), item.vote_server_signature)

    def sign_block(self, block_hash: str) -> str:
        return sign(self.keys.private_key, block_hash.encode("ascii"))


class ValidatorNetwork:
    def __init__(
        self,
        validators: list[Validator],
        auth_server: AuthenticationServer,
        voting_server: VotingServer,
        blockchain: Blockchain,
    ) -> None:
        if len(validators) < 3:
            raise ValueError("at least three validators are required")
        self.validators = validators
        self.auth_server = auth_server
        self.voting_server = voting_server
        self.blockchain = blockchain
        self.threshold = len(validators) // 2 + 1
        self._next_proposer = 0

    @property
    def notifier(self) -> Validator:
        return self.validators[0]

    def process_pool(self, vote_pool: VotePool, flush: bool = False) -> list[Block]:
        accepted_blocks: list[Block] = []
        while len(vote_pool) >= self.blockchain.block_size or (flush and len(vote_pool) > 0):
            batch = vote_pool.pop_batch(self.blockchain.block_size)
            block = self._propose_block(batch)
            approvals = self._collect_approvals(block)
            if len(approvals) >= self.threshold:
                block.acceptor_signatures.update(approvals)
                self.blockchain.append(block)
                self._reissue_tickets_for_rejected_transactions(block)
                self._notify_receipts(block)
                accepted_blocks.append(block)
        return accepted_blocks

    def _propose_block(self, batch: list[VotePoolItem]) -> Block:
        proposer = self.validators[self._next_proposer]
        self._next_proposer = (self._next_proposer + 1) % len(self.validators)

        transactions: list[VoteTransaction] = []
        seen_tickets: set[str] = set()
        for item in batch:
            ticket = item.payload.credential.ticket
            is_valid = proposer.validate_item(
                item,
                self.auth_server.public_key_pem,
                self.voting_server.public_key_pem,
                self.blockchain,
            )
            if ticket in seen_tickets:
                is_valid = False
            seen_tickets.add(ticket)
            transactions.append(
                VoteTransaction(
                    ticket,
                    item.payload.encrypted_vote,
                    "accepted" if is_valid else "rejected",
                )
            )
        header = BlockHeader(
            index=len(self.blockchain.blocks),
            election_id=self.blockchain.election_id,
            previous_hash=self.blockchain.last_hash,
            timestamp=datetime.now(UTC).isoformat(),
            tx_count=len(transactions),
            merkle_root=merkle_root(transactions, self.blockchain.block_size),
            proposer_id=proposer.validator_id,
        )
        block_hash = sha256_hex(canonical_json(header))
        return Block(
            header=header,
            transactions=transactions,
            block_hash=block_hash,
            proposer_signature=proposer.sign_block(block_hash),
        )

    def _collect_approvals(self, block: Block) -> dict[str, str]:
        approvals = {block.header.proposer_id: block.proposer_signature}
        seen_accepted_tickets: set[str] = set()
        if block.header.previous_hash != self.blockchain.last_hash:
            return {}
        if block.header.merkle_root != merkle_root(block.transactions, self.blockchain.block_size):
            return {}
        if block.block_hash != sha256_hex(canonical_json(block.header)):
            return {}
        for tx in block.transactions:
            if tx.status != "accepted":
                continue
            if tx.ticket in seen_accepted_tickets or self.blockchain.contains_ticket(tx.ticket):
                return {}
            seen_accepted_tickets.add(tx.ticket)
        for validator in self.validators:
            if validator.validator_id in approvals:
                continue
            approvals[validator.validator_id] = validator.sign_block(block.block_hash)
            if len(approvals) >= self.threshold:
                break
        return approvals

    def _notify_receipts(self, block: Block) -> None:
        for tx in block.transactions:
            if tx.status != "accepted":
                continue
            unsigned_receipt = Receipt(
                election_id=block.header.election_id,
                block_index=block.header.index,
                tx_hash=tx.tx_hash,
                merkle_proof=merkle_proof(block.transactions, self.blockchain.block_size, tx.tx_hash),
                notifier_signature="",
            )
            receipt = Receipt(
                unsigned_receipt.election_id,
                unsigned_receipt.block_index,
                unsigned_receipt.tx_hash,
                unsigned_receipt.merkle_proof,
                sign(self.notifier.keys.private_key, unsigned_receipt.signable()),
            )
            self.auth_server.store_receipt(tx.ticket, receipt)

    def _reissue_tickets_for_rejected_transactions(self, block: Block) -> None:
        accepted_tickets = {tx.ticket for tx in block.transactions if tx.status == "accepted"}
        for tx in block.transactions:
            if tx.status != "rejected":
                continue
            if tx.ticket in accepted_tickets:
                continue
            self.auth_server.reissue_ticket_for_rejected_vote(tx.ticket)


class ScrutinyAuthority:
    def __init__(self, election: Election) -> None:
        self.election = election
        self.keys = generate_rsa_keypair()

    @property
    def public_key_pem(self) -> str:
        return public_key_to_pem(self.keys.public_key)

    def tally(self, blockchain: Blockchain) -> Counter[str]:
        counts: Counter[str] = Counter({choice: 0 for choice in self.election.choices})
        for block in blockchain.blocks:
            for tx in block.transactions:
                if tx.status != "accepted":
                    continue
                choice = decrypt_with(self.keys.private_key, tx.encrypted_vote).decode("utf-8")
                self.election.validate_choice(choice)
                counts[choice] += 1
        return counts


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


def build_demo_system() -> tuple[
    Election,
    AuthenticationServer,
    ScrutinyAuthority,
    VotingServer,
    VotePool,
    Blockchain,
    ValidatorNetwork,
]:
    election = Election("Elezione1", ("Lista A", "Lista B", "Lista C"))
    auth = AuthenticationServer(election, {"VR001", "VR002", "VR003", "VR004", "VR005"})
    scrutiny = ScrutinyAuthority(election)
    voting = VotingServer(auth.public_key_pem)
    pool = VotePool()
    blockchain = Blockchain(election.election_id)
    validators = [Validator(f"validator-{i}") for i in range(1, 6)]
    network = ValidatorNetwork(validators, auth, voting, blockchain)
    return election, auth, scrutiny, voting, pool, blockchain, network
