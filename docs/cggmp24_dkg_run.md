# CGGMP24 AUX + DKG Runbook

This runbook starts AUX provisioning first, then runs CGGMP24 t-of-n DKG.

## Prereqs
- Configure nodes `1..N` with consistent `nodes.sharedSecret` (HMAC) and `nodes.peers`.
- Ensure `Constants.NODES_COUNT` and `Constants.THRESHOLD` match your test.
- If you enable TLS, generate a dev cert/key via `scripts/generate_dev_tls.sh` and set:
  - `nodes.ssl.enabled: true`
  - `nodes.ssl.cert: config/node.crt`
  - `nodes.ssl.key: config/node.key`
  - `nodes.ssl.trustCert: config/ca.crt`

## Step 1: Start nodes
Start all nodes with unique `node.id` and `node.port`.

## Step 2: AUX provisioning
Call on any node (usually the initiator):

```
POST /api/cggmp/aux/start
```

Poll status:

```
GET /api/cggmp/aux/status?taskId=<taskId>
```

Wait until status is `COMPLETED` on all nodes.

## Step 3: DKG
Call on any node (usually the initiator):

```
POST /api/cggmp/dkg/start
```

Poll status:

```
GET /api/cggmp/dkg/status?taskId=<taskId>
```

When completed, read the group public key:

```
GET /api/cggmp/dkg/public-key?taskId=<taskId>
```

## Notes
- AUX info is persisted per-node in `databases/share_<nodeId>.db`.
- DKG stores `public_shares` and `index_map` alongside the local share.
- If AUX was not run, DKG will fail with "Missing auxiliary info".
