# SCAN public FOREX contract 1.0

FOREX imports only `SCANConfig`, `SCANService`, `FOREXSCANWorkflow`,
`SCANResponseV1` and `SCANError`. It does not import acquisition, commands,
snapshots, feed, outbox or filesystem implementation modules.

Every successful operation returns a deterministic `SCANResponseV1` document:

```json
{"schema_version":"1.0","status":"success","data":{},"errors":[],"metadata":{}}
```

Public reads never execute probes. Probe timeout and error remain scan evidence,
not API failures. SCAN reports evidence; FOREX retains interpretation,
correlation, scoring and decisions.
