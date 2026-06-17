from __future__ import annotations

from dataclasses import dataclass
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from .crypto import public_key_from_pem, sha256_hex, verify
from .merkle import verify_merkle_proof
from .models import Credential, Receipt, VotePayload
from .services import CheckResult, VoterClient, build_demo_system


VOTER_IDS = ("VR001", "VR002", "VR003", "VR004", "VR005")
SCENARIOS = (
    "Normale",
    "Firma credenziale manomessa",
    "Firma anonima manomessa",
    "Server voto compromesso",
)

ALERT_ERROR_MESSAGES = {
    "voter is not eligible for this election": "L'elettore selezionato non ha diritto di voto per questa elezione.",
    "this voter already has an accepted vote": "Per questo elettore esiste gia un voto accettato.",
    "unknown ticket": "Il ticket della credenziale non e riconosciuto dal server di autenticazione.",
    "credential refers to a different election": "La credenziale appartiene a un'altra elezione.",
    "ticket already used": "Questo ticket e gia stato usato per inviare un voto.",
    "replayed nonce": "Il nonce del voto e gia stato usato.",
    "invalid authentication-server signature": "La firma del server di autenticazione non e valida.",
    "invalid anonymous voter signature": "La firma anonima dell'elettore non e valida.",
    "block does not point to current chain head": "Il blocco non punta alla testa corrente della blockchain.",
    "at least three validators are required": "Sono necessari almeno tre validatori.",
    "data_list must not be empty": "La lista dei dati non puo essere vuota.",
    "transaction is not in this block": "La transazione non e presente in questo blocco.",
    "expected an RSA public key": "Era attesa una chiave pubblica RSA.",
}


@dataclass
class UserSession:
    client: VoterClient
    credential: Credential | None = None
    auth_signature: str | None = None
    payload: VotePayload | None = None
    submitted: bool = False
    receipt_revealed: bool = False


class ProtocolDemoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("EVOTE gruppo 30")
        self.geometry("1100x720")
        self.minsize(980, 620)

        self.voter_var = tk.StringVar(value=VOTER_IDS[0])
        self.choice_var = tk.StringVar()
        self.scenario_vars = {name: tk.BooleanVar(value=False) for name in SCENARIOS if name != "Normale"}
        self.scenario_buttons: dict[str, ttk.Checkbutton] = {}
        self.credential_var = tk.StringVar()
        self.receipt_var = tk.StringVar()
        self.ballot_var = tk.StringVar()
        self.pool_var = tk.StringVar()
        self.blocks_var = tk.StringVar()
        self.status_var = tk.StringVar()

        self._build_widgets()
        self.reset_protocol()

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self, padding=(16, 14, 16, 8))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Elezione Sicura Demo", font=("Segoe UI", 17, "bold")).grid(
            row=0,
            column=0,
            sticky="w",
        )
        ttk.Label(header, textvariable=self.status_var).grid(row=0, column=1, sticky="e")

        stats = ttk.Frame(self, padding=(16, 0, 16, 10))
        stats.grid(row=1, column=0, sticky="ew")
        ttk.Label(stats, textvariable=self.pool_var).grid(row=0, column=0, sticky="w", padx=(0, 24))
        ttk.Label(stats, textvariable=self.blocks_var).grid(row=0, column=1, sticky="w", padx=(0, 24))

        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 16))

        voter_area = ttk.Frame(body)
        voter_area.columnconfigure(0, weight=1)
        voter_area.rowconfigure(5, weight=1)
        body.add(voter_area, weight=3)

        self._build_voter_panel(voter_area)

        system_area = ttk.Frame(body)
        system_area.columnconfigure(0, weight=1)
        system_area.rowconfigure(2, weight=1)
        system_area.rowconfigure(4, weight=1)
        system_area.rowconfigure(6, weight=1)
        body.add(system_area, weight=2)

        self._build_system_panel(system_area)

    def _build_voter_panel(self, parent: ttk.Frame) -> None:
        access = ttk.LabelFrame(parent, text="1. Accesso dell'elettore", padding=12)
        access.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        access.columnconfigure(3, weight=1)

        ttk.Label(access, text="Tessera").grid(row=0, column=0, sticky="w")
        self.voter_combo = ttk.Combobox(access, textvariable=self.voter_var, values=VOTER_IDS, width=10, state="readonly")
        self.voter_combo.grid(row=1, column=0, sticky="w", padx=(0, 12))
        self.voter_combo.bind("<<ComboboxSelected>>", lambda _event: self.switch_voter())

        self.credential_button = ttk.Button(access, text="Richiedi credenziale / ricevuta", command=self.request_credential)
        self.credential_button.grid(row=1, column=1, padx=(0, 8))

        self.verify_button = ttk.Button(access, text="Verifica ricevuta", command=self.verify_receipt)
        self.verify_button.grid(row=1, column=2, padx=(0, 8))

        ballot = ttk.LabelFrame(parent, text="2. Preparazione della scheda", padding=12)
        ballot.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        ballot.columnconfigure(5, weight=1)

        ttk.Label(ballot, text="Lista").grid(row=0, column=0, sticky="w")
        self.choice_combo = ttk.Combobox(ballot, textvariable=self.choice_var, width=16, state="readonly")
        self.choice_combo.grid(row=1, column=0, sticky="w", padx=(0, 12))

        ttk.Label(ballot, text="Scenari").grid(row=0, column=1, sticky="w")
        scenario_box = ttk.Frame(ballot)
        scenario_box.grid(row=1, column=1, sticky="w", padx=(0, 12))
        for index, scenario in enumerate(name for name in SCENARIOS if name != "Normale"):
            scenario_button = ttk.Checkbutton(
                scenario_box,
                text=scenario,
                variable=self.scenario_vars[scenario],
            )
            scenario_button.grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 10))
            self.scenario_buttons[scenario] = scenario_button

        self.prepare_button = ttk.Button(ballot, text="Prepara voto cifrato", command=self.prepare_ballot)
        self.prepare_button.grid(row=1, column=2, padx=(0, 8))

        self.submit_button = ttk.Button(ballot, text="Invia al server di voto", command=self.submit_ballot)
        self.submit_button.grid(row=1, column=3, padx=(0, 8))

        ttk.Label(ballot, textvariable=self.ballot_var).grid(row=1, column=5, sticky="w")

        verification = ttk.LabelFrame(parent, text="3. Avanzamento dei validatori", padding=12)
        verification.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        self.process_button = ttk.Button(verification, text="Fai avanzare i validatori", command=self.process_pool)
        self.process_button.grid(row=0, column=0, sticky="w")

        details = ttk.LabelFrame(parent, text="Dettagli visibili all'utente", padding=12)
        details.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        details.columnconfigure(0, weight=1)
        details.columnconfigure(1, weight=1)

        credential_panel = ttk.LabelFrame(details, text="Credenziale", padding=10)
        credential_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        credential_panel.columnconfigure(0, weight=1)
        ttk.Label(credential_panel, textvariable=self.credential_var, justify="left").grid(row=0, column=0, sticky="nw")

        receipt_panel = ttk.LabelFrame(details, text="Ricevuta", padding=10)
        receipt_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        receipt_panel.columnconfigure(0, weight=1)
        ttk.Label(receipt_panel, textvariable=self.receipt_var, justify="left").grid(row=0, column=0, sticky="nw")

        log_frame = ttk.Frame(parent)
        log_frame.grid(row=5, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)
        ttk.Label(log_frame, text="Log della procedura", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        self.log = scrolledtext.ScrolledText(log_frame, height=4, wrap=tk.WORD, state="disabled")
        self.log.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

    def _build_system_panel(self, parent: ttk.Frame) -> None:
        actions = ttk.Frame(parent)
        actions.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        actions.columnconfigure(2, weight=1)

        ttk.Button(actions, text="Scrutinio", command=self.show_tally).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(actions, text="Reset simulazione", command=self.reset_protocol).grid(row=0, column=1, padx=(0, 8))

        ttk.Label(parent, text="Blockchain pubblica read-only", font=("Segoe UI", 10, "bold")).grid(
            row=1,
            column=0,
            sticky="nw",
        )
        self.blocks_table = ttk.Treeview(
            parent,
            columns=("index", "tx", "proposer", "approvals", "hash"),
            show="headings",
            height=6,
        )
        self.blocks_table.heading("index", text="Blocco")
        self.blocks_table.heading("tx", text="Voti")
        self.blocks_table.heading("proposer", text="Proposer")
        self.blocks_table.heading("approvals", text="Consenso")
        self.blocks_table.heading("hash", text="Hash")
        self.blocks_table.column("index", width=70, anchor="center")
        self.blocks_table.column("tx", width=55, anchor="center")
        self.blocks_table.column("proposer", width=105)
        self.blocks_table.column("approvals", width=80, anchor="center")
        self.blocks_table.column("hash", width=170)
        self.blocks_table.grid(row=2, column=0, sticky="nsew", pady=(6, 14))

        ttk.Label(parent, text="Scrutinio finale", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="nw")
        self.tally_box = scrolledtext.ScrolledText(parent, height=4, wrap=tk.WORD, state="disabled")
        self.tally_box.grid(row=4, column=0, sticky="nsew", pady=(6, 0))

        checks = ttk.LabelFrame(parent, text="Controlli del protocollo", padding=12)
        checks.grid(row=5, column=0, sticky="nsew", pady=(12, 0))
        checks.columnconfigure(0, weight=1)
        checks.rowconfigure(0, weight=1)
        self.checks_table = ttk.Treeview(
            checks,
            columns=("phase", "name", "result", "detail"),
            show="headings",
            height=6,
        )
        self.checks_table.heading("phase", text="Fase")
        self.checks_table.heading("name", text="Controllo")
        self.checks_table.heading("result", text="Esito")
        self.checks_table.heading("detail", text="Descrizione")
        self.checks_table.column("phase", width=110)
        self.checks_table.column("name", width=180)
        self.checks_table.column("result", width=60, anchor="center")
        self.checks_table.column("detail", width=320)
        self.checks_table.grid(row=0, column=0, sticky="nsew")

    def reset_protocol(self) -> None:
        (
            self.election,
            self.auth,
            self.scrutiny,
            self.voting,
            self.pool,
            self.blockchain,
            self.network,
        ) = build_demo_system()
        self.sessions = {voter_id: UserSession(VoterClient(voter_id)) for voter_id in VOTER_IDS}
        for scenario_var in self.scenario_vars.values():
            scenario_var.set(False)
        self.choice_combo.configure(values=self.election.choices)
        self.voter_var.set(VOTER_IDS[0])
        self.choice_var.set(self.election.choices[0])
        self._clear_log()
        self._clear_tally()
        self._clear_checks()
        self._log_event("Inizializzazione")
        self._log("Simulazione inizializzata.")
        self._log("Seleziona l'elettore e richiedi la credenziale di voto.")
        self._refresh()

    def switch_voter(self) -> None:
        self._log_event("Cambio elettore")
        self._log(f"Sessione utente selezionata: {self.voter_var.get()}.")
        self._refresh()

    def request_credential(self) -> None:
        voter_id = self.voter_var.get()
        session = self.sessions[voter_id]
        self._log_event(f"Richiesta credenziale - {voter_id}")
        fingerprint = sha256_hex(session.client.anon_public_key_pem.encode("utf-8"))[:16]
        self._log(f"{voter_id}: identita presentata al server di autenticazione.")
        self._log(f"{voter_id}: chiave anonima generata, fingerprint {fingerprint}.")
        checks = self.auth.inspect_credential_request(voter_id)
        self._record_checks("Autenticazione", checks)
        receipt = self.auth.get_receipt(voter_id)
        if receipt is not None:
            session.receipt_revealed = True
            self._log(f"{voter_id}: esiste gia una ricevuta, il server di autenticazione la restituisce.")
            self._log(f"{voter_id}: la ricevuta e ora visibile nei dettagli utente.")
            self._refresh()
            return
        try:
            credential, auth_signature = self.auth.issue_credential(voter_id, session.client.anon_public_key_pem)
        except Exception as exc:
            self._show_error("Credenziale non emessa", exc)
            return
        previous_ticket = session.credential.ticket if session.credential is not None else None
        session.credential = credential
        session.auth_signature = auth_signature
        self._log(f"{voter_id}: credenziale ricevuta dal server di autenticazione.")
        if previous_ticket is not None and previous_ticket != credential.ticket:
            self._log(
                f"{voter_id}: il ticket precedente era stato rifiutato nel blocco, "
                "il server di autenticazione ne ha generato uno nuovo."
            )
        self._log(f"{voter_id}: ticket anonimo {credential.ticket[:14]}...")
        self._refresh()

    def prepare_ballot(self) -> None:
        voter_id = self.voter_var.get()
        session = self.sessions[voter_id]
        self._log_event(f"Preparazione scheda - {voter_id}")
        if session.credential is None or session.auth_signature is None:
            session.payload = session.client.build_vote(
                self.election,
                self.scrutiny.public_key_pem,
                self.choice_var.get(),
            )
            self._log(f"{voter_id}: ! scheda preparata senza credenziale !")
        else:
            try:
                session.payload = session.client.build_vote(
                    self.election,
                    self.scrutiny.public_key_pem,
                    self.choice_var.get(),
                    credential=session.credential,
                    auth_signature=session.auth_signature,
                )
                self._log(f"{voter_id}: preferenza cifrata per l'autorita di scrutinio.")
            except Exception as exc:
                self._show_error("Scheda non preparata", exc)
                return
        self._log(f"{voter_id}: scheda firmata con la chiave anonima.")
        selected_scenarios = self._selected_scenarios()
        if selected_scenarios:
            self._log(f"{voter_id}: scenari selezionati {', '.join(selected_scenarios)}.")
        self._refresh()

    def submit_ballot(self) -> None:
        voter_id = self.voter_var.get()
        session = self.sessions[voter_id]
        self._log_event(f"Invio voto - {voter_id}")
        if session.payload is None:
            messagebox.showinfo("Scheda mancante", "Prepara prima il voto cifrato.")
            return
        payload = self._payload_for_submission(session)
        selected_scenarios = self._selected_scenarios()
        compromised_server = "Server voto compromesso" in selected_scenarios
        if not compromised_server:
            checks = self.voting.inspect_payload(payload)
            self._record_checks("Server di voto", checks)
        try:
            if compromised_server:
                self._log(
                    f"{voter_id}: server di voto compromesso, il payload viene firmato e inoltrato senza controlli."
                )
                self.voting.forward_vote_unchecked(payload, self.pool)
            else:
                self.voting.receive_vote(payload, self.pool)
        except Exception as exc:
            self._show_error("Voto rifiutato", exc)
            return
        session.submitted = True
        self._log(f"{voter_id}: voto inviato al server di voto.")
        self._log(f"{voter_id}: controlli superati, voto inserito nella Vote Pool.")
        if len(self.pool) >= self.blockchain.block_size:
            self._log(
                f"Vote Pool: raggiunta la soglia di {self.blockchain.block_size} voti, "
                "avvio automatico dei validatori."
            )
            self.process_pool(auto_triggered=True)
            return
        self._refresh()

    def process_pool(self, auto_triggered: bool = False) -> None:
        self._log_event("Validazione automatica" if auto_triggered else "Validazione distribuita")
        if len(self.pool) == 0:
            self._log("Vote Pool vuota: nessun voto da validare.")
            self._refresh()
            return
        proposer = self.network.validators[self.network._next_proposer]
        batch = self.pool._items[: self.blockchain.block_size]
        for item in batch:
            checks = proposer.inspect_item(
                item,
                self.auth.public_key_pem,
                self.voting.public_key_pem,
                self.blockchain,
            )
            self._record_checks(f"Validatore {proposer.validator_id}", checks)
        blocks = self.network.process_pool(self.pool, flush=True)
        if not blocks:
            self._log("I validatori non hanno accettato nuovi blocchi.")
        for block in blocks:
            accepted_count = sum(1 for tx in block.transactions if tx.status == "accepted")
            rejected_count = sum(1 for tx in block.transactions if tx.status == "rejected")
            self._log(
                f"Validatori: blocco {block.header.index} accettato con "
                f"{len(block.acceptor_signatures)}/5 firme."
            )
            self._log(
                f"Validatori: transazioni nel blocco -> accepted={accepted_count}, rejected={rejected_count}."
            )
            self._log("Notificatore: ricevute inviate al server di autenticazione.")
        self._refresh()

    def _verify_receipt_for_voter(self, voter_id: str, show_dialog: bool) -> None:
        self._log_event(f"Verifica ricevuta - {voter_id}")
        receipt = self.auth.get_receipt(voter_id)
        if receipt is None:
            self._log(f"{voter_id}: ricevuta non ancora disponibile.")
            if show_dialog:
                messagebox.showinfo("Ricevuta non disponibile", "Fai avanzare i validatori prima della verifica.")
            return

        self._log(f"{voter_id}: ricevuta ottenuta dal server di autenticazione.")
        self._log(
            f"{voter_id}: controllo block_index={receipt.block_index}, "
            f"tx_hash={receipt.tx_hash[:18]}..., election_id={receipt.election_id}."
        )

        signature_ok = verify(
            public_key_from_pem(self.network.notifier.public_key_pem),
            receipt.signable(),
            receipt.notifier_signature,
        )
        self._log(
            f"{voter_id}: verifica firma del notificatore -> {'OK' if signature_ok else 'NO'}."
        )

        block_ok = receipt.block_index < len(self.blockchain.blocks)
        if not block_ok:
            self._log(f"{voter_id}: il blocco indicato dalla ricevuta non esiste nella blockchain.")
            ok = False
        else:
            block = self.blockchain.blocks[receipt.block_index]
            self._log(
                f"{voter_id}: blocco {block.header.index} trovato, merkle_root={block.header.merkle_root[:18]}..."
            )
            election_ok = block.header.election_id == receipt.election_id
            self._log(
                f"{voter_id}: confronto election_id ricevuta/header -> {'OK' if election_ok else 'NO'}."
            )

            tx_entry = self.blockchain.find_transaction(receipt.tx_hash)
            tx_ok = tx_entry is not None and tx_entry[0].header.index == block.header.index
            self._log(
                f"{voter_id}: ricerca della transazione in blockchain -> {'OK' if tx_ok else 'NO'}."
            )

            current_hash = sha256_hex(receipt.tx_hash.encode("utf-8"))
            self._log(
                f"{voter_id}: hash iniziale della foglia -> {current_hash[:18]}..."
            )
            for step_index, step in enumerate(receipt.merkle_proof, start=1):
                if step.sibling_position == "left":
                    current_hash = sha256_hex((step.sibling_hash + current_hash).encode("utf-8"))
                else:
                    current_hash = sha256_hex((current_hash + step.sibling_hash).encode("utf-8"))
                self._log(
                    f"{voter_id}: proof step {step_index} ({step.sibling_position}) -> "
                    f"hash parziale {current_hash[:18]}..."
                )

            merkle_ok = verify_merkle_proof(receipt.tx_hash, receipt.merkle_proof, block.header.merkle_root)
            self._log(
                f"{voter_id}: root ricostruita {'coincide' if merkle_ok else 'non coincide'} con quella del blocco."
            )

            ok = signature_ok and election_ok and tx_ok and merkle_ok

        result = "OK" if ok else "FALLITA"
        self._log(f"{voter_id}: verifica individuale {result}, tx {receipt.tx_hash[:14]}...")
        if show_dialog:
            messagebox.showinfo("Verifica individuale", f"Verifica {result}")
        self._refresh()

    def verify_receipt(self) -> None:
        voter_id = self.voter_var.get()
        session = self.sessions[voter_id]
        if not session.receipt_revealed:
            self._log_event(f"Verifica ricevuta - {voter_id}")
            self._log(f"{voter_id}: richiedi prima la ricevuta al server di autenticazione.")
            messagebox.showinfo("Ricevuta non richiesta", "Premi prima 'Richiedi credenziale' per ottenere la ricevuta.")
            return
        self._verify_receipt_for_voter(voter_id, show_dialog=True)

    def show_tally(self) -> None:
        self._log_event("Scrutinio")
        tally = self.scrutiny.tally(self.blockchain)
        self._clear_tally()
        self._write_tally("Risultato pubblicato dall'autorita di scrutinio\n\n")
        for choice, count in tally.items():
            self._write_tally(f"{choice}: {count}\n")
        self._log("Scrutinio finale aggiornato.")
        self._refresh()

    def _refresh(self) -> None:
        voter_id = self.voter_var.get()
        session = self.sessions[voter_id]
        receipt = self.auth.get_receipt(voter_id)
        visible_receipt = receipt if session.receipt_revealed else None
        credential_tampering = "Firma credenziale manomessa"
        can_tamper_credential = session.credential is not None and session.auth_signature is not None

        if not can_tamper_credential:
            self.scenario_vars[credential_tampering].set(False)
        self.scenario_buttons[credential_tampering].configure(
            state="normal" if can_tamper_credential else "disabled"
        )

        self.status_var.set(f"Elezione: {self.election.election_id}")
        self.pool_var.set(f"Vote Pool: {len(self.pool)}")
        self.blocks_var.set(f"Blocchi registrati: {len(self.blockchain.blocks)}")

        if session.credential is None:
            self.credential_var.set("Credenziale: non ancora richiesta")
        else:
            anon_fp = sha256_hex(session.credential.anon_public_key_pem.encode("utf-8"))[:16]
            self.credential_var.set(
                f"election_id: {session.credential.election_id}\n"
                f"ticket: {session.credential.ticket[:18]}...\n"
                f"chiave anonima: {anon_fp}\n"
                f"firma server autenticazione: {session.auth_signature[:18]}...\n"
            )

        if session.payload is None:
            self.ballot_var.set("Scheda: non preparata")
        elif session.submitted:
            self.ballot_var.set(f"Scheda inviata, nonce {session.payload.nonce[:10]}...")
        else:
            self.ballot_var.set(f"Scheda cifrata pronta, nonce {session.payload.nonce[:10]}...")

        if visible_receipt is None:
            self.receipt_var.set("Ricevuta: non disponibile")
        else:
            self.receipt_var.set(
                f"election_id: {visible_receipt.election_id}\n"
                f"block_index: {visible_receipt.block_index}\n"
                f"tx_hash: {visible_receipt.tx_hash[:18]}...\n"
                f"notifier_signature: {visible_receipt.notifier_signature[:18]}...\n"
                "merkle proof\n"
                f"{self._format_merkle_proof(visible_receipt)}"
            )

        self.credential_button.configure(state="normal") # state="disabled" if session.credential else "normal"
        self.prepare_button.configure(state="normal") # state="normal" if session.credential and not session.payload else "disabled"
        self.submit_button.configure(state="normal" if session.payload else "disabled") # state="normal" if session.payload and not session.submitted
        self.verify_button.configure(state="normal" if session.receipt_revealed else "disabled")

        for item in self.blocks_table.get_children():
            self.blocks_table.delete(item)
        for block in self.blockchain.blocks:
            self.blocks_table.insert(
                "",
                tk.END,
                values=(
                    block.header.index,
                    block.header.tx_count,
                    block.header.proposer_id,
                    f"{len(block.acceptor_signatures)}/5",
                    block.block_hash[:20] + "...",
                ),
            )

    def _show_error(self, title: str, exc: Exception) -> None:
        message = self._localized_error_message(exc)
        self._log(f"{title}: {message}")
        messagebox.showerror(title, message)
        self._refresh()

    def _localized_error_message(self, exc: Exception) -> str:
        raw_message = str(exc).strip()
        normalized_message = raw_message.strip("'\"")
        if normalized_message.startswith("invalid choice: "):
            choice = normalized_message.removeprefix("invalid choice: ")
            return f"Scelta non valida: {choice}"
        return ALERT_ERROR_MESSAGES.get(
            normalized_message,
            normalized_message or "Si e verificato un errore imprevisto.",
        )

    def _payload_for_submission(self, session: UserSession) -> VotePayload:
        assert session.payload is not None
        payload = session.payload
        selected_scenarios = self._selected_scenarios()
        if "Firma credenziale manomessa" in selected_scenarios:
            payload = VotePayload(
                payload.credential,
                payload.auth_signature[:-2] + "AA",
                payload.nonce,
                payload.encrypted_vote,
                payload.anon_signature,
            )
        if "Firma anonima manomessa" in selected_scenarios:
            payload = VotePayload(
                payload.credential,
                payload.auth_signature,
                payload.nonce,
                payload.encrypted_vote,
                payload.anon_signature[:-2] + "AA",
            )
        return payload

    def _selected_scenarios(self) -> list[str]:
        return [name for name, enabled in self.scenario_vars.items() if enabled.get()]

    def _record_checks(self, phase: str, checks: list[CheckResult]) -> None:
        for check in checks:
            self.checks_table.insert(
                "",
                tk.END,
                values=(phase, check.name, "OK" if check.passed else "NO", check.detail),
            )

    def _clear_checks(self) -> None:
        for item in self.checks_table.get_children():
            self.checks_table.delete(item)

    def _log_event(self, name: str) -> None:
        self._log(f"---- {name} ----")

    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", tk.END)
        self.log.configure(state="disabled")

    def _write_tally(self, text: str) -> None:
        self.tally_box.configure(state="normal")
        self.tally_box.insert(tk.END, text)
        self.tally_box.configure(state="disabled")

    def _clear_tally(self) -> None:
        self.tally_box.configure(state="normal")
        self.tally_box.delete("1.0", tk.END)
        self.tally_box.configure(state="disabled")

    def _format_receipt_details(self, receipt: Receipt | None) -> str:
        if receipt is None:
            return "Ricevuta: non disponibile"
        proof_lines = []
        for index, step in enumerate(receipt.merkle_proof, start=1):
            proof_lines.append(
                f"  {index}. {step.sibling_position} -> {step.sibling_hash}"
            )
        proof_text = "\n".join(proof_lines) if proof_lines else "  nessuno"
        return (
            f"election_id: {receipt.election_id}\n"
            f"block_index: {receipt.block_index}\n"
            f"tx_hash: {receipt.tx_hash}\n"
            f"notifier_signature: {receipt.notifier_signature}\n"
            "merkle_proof:\n"
            f"{proof_text}"
        )

    def _format_merkle_proof(self, receipt: Receipt) -> str:
        if not receipt.merkle_proof:
            return "Mancante!"
        lines = []
        for index, step in enumerate(receipt.merkle_proof, start=1):
            lines.append(f"  sibling: {step.sibling_position}; hash: {step.sibling_hash[:10]}...")
        return "\n".join(lines)


def main() -> None:
    app = ProtocolDemoApp()
    app.mainloop()


if __name__ == "__main__":
    main()
