# APS_VotoElettronico_Gruppo30

Demo didattica standalone, in Python, del protocollo di voto elettronico
descritto nel WP2.

La demo simula in memoria:

- server di autenticazione e rilascio della credenziale anonima;
- server di voto e Vote Pool;
- validatori con consenso 3 su 5;
- blockchain append-only con Merkle root;
- ricevuta per la verifica individuale;
- autorita di scrutinio e conteggio finale.

## Avvio rapido

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
python -m evote_demo
```

In alternativa, dopo l'installazione:

```bash
evote-demo
```

La finestra simula la procedura dal punto di vista dell'elettore:

- accesso con tessera elettorale simulata;
- richiesta della credenziale anonima;
- scelta della lista;
- preparazione della scheda cifrata e firmata;
- invio al server di voto;
- avanzamento dei validatori;
- richiesta e verifica della ricevuta individuale;
- consultazione della blockchain read-only e dello scrutinio.

La GUI evidenzia anche i controlli eseguiti nelle varie fasi:

- verifiche del server di autenticazione sulla richiesta di credenziale;
- verifiche del server di voto su nonce, ticket e firme;
- verifiche del validatore sulla coerenza del payload prima del blocco.

Per completezza e possibile selezionare anche scenari pilotati non validi:

- firma della credenziale manomessa;
- firma anonima manomessa;
- server di voto compromesso.

## Prestazioni sperimentali

La cartella `performance/` contiene script da terminale per misurare costo
computazionale, dimensione dei messaggi, latenza delle verifiche e tempi di
interazione della proof of concept.

Esecuzione completa:

```bash
python performance/run_all.py
```

che di default coincide con lo scenario della demo:

```bash
python performance/run_all.py --samples 20 --voters 5
```

Scenario usato per i risultati sotto: 5 voti, blocchi da 4 transazioni,
5 validatori, consenso 3 su 5. I tempi sono misurati localmente con
`time.perf_counter_ns()`: la demo gira in memoria e non include latenza di rete,
database o processi distribuiti reali.

### Costo computazionale delle operazioni crittografiche

| Operazione | N | Media ms | Mediana ms |
| --- | ---: | ---: | ---: |
| SHA-256 su payload voto | 20 | 0.0121 | 0.0120 |
| Firma RSA-PSS credenziale | 20 | 0.3392 | 0.2308 |
| Verifica firma RSA-PSS credenziale | 20 | 0.0249 | 0.0247 |
| Cifratura RSA-OAEP voto | 20 | 0.0235 | 0.0234 |
| Decifratura RSA-OAEP voto | 20 | 0.2275 | 0.2268 |
| Costruzione Merkle root blocco | 20 | 0.0798 | 0.0777 |
| Generazione Merkle proof | 20 | 0.1561 | 0.0943 |
| Verifica Merkle proof | 20 | 0.0121 | 0.0120 |

Le operazioni piu costose nella simulazione sono firma e decifratura RSA. Gli
hash e la verifica della Merkle proof risultano invece molto leggeri.

### Dimensione dei messaggi scambiati

| Messaggio/Dato | Byte | Contenuto principale |
| --- | ---: | --- |
| Credenziale anonima | 570 | ticket + chiave pubblica anonima PEM |
| Firma server autenticazione | 344 | firma RSA-2048 in base64 |
| Payload voto cifrato | 1712 | credenziale + nonce + voto cifrato + firme |
| Item Vote Pool | 2095 | payload + firma server voto |
| Transazione nel blocco | 440 | ticket + voto cifrato + stato |
| Blocco | 3639 | header + transazioni + firme validatori |
| Ricevuta | 730 | tx_hash + Merkle proof + firma notificatore |
| Merkle proof | 223 | 2 passi |
| Firma notificatore | 344 | firma RSA-2048 in base64 |
| Chiave pubblica validatore | 451 | PEM SubjectPublicKeyInfo |

Le dimensioni sono dominate da firme RSA, ciphertext RSA e chiavi pubbliche PEM.
Nel blocco misurato la Merkle proof ha 2 passi; in generale cresce in modo
logaritmico rispetto alla dimensione del blocco.

### Latenza delle verifiche e tempi di interazione

| Operazione | N | Media ms | Mediana ms |
| --- | ---: | ---: | ---: |
| Interazione: rilascio credenziale | 20 | 0.7646 | 0.7325 |
| Interazione: preparazione scheda | 20 | 0.7354 | 0.7185 |
| Interazione: invio al server voto | 20 | 0.7504 | 0.7482 |
| Validazione: avanzamento validatori | 20 | 5.4242 | 5.3407 |
| Verifica: ricevuta individuale | 20 | 0.0922 | 0.0847 |
| Scrutinio: conteggio finale | 20 | 1.6108 | 1.5931 |

La verifica individuale della ricevuta e rapida perche combina una verifica di
firma con una Merkle proof corta. L'avanzamento dei validatori e piu costoso
perche include validazione dei payload, costruzione del blocco, calcolo della
Merkle root e firme dei validatori.

## Nota

Il progetto e una proof of concept per WP4: non implementa server reali,
persistenza su database o una CA X.509 completa. L'obiettivo e mostrare il
flusso crittografico principale in modo semplice.
