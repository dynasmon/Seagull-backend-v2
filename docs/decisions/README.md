# Architecture decisions

Each record states what forced the decision, what was decided, and what the
decision costs. They are written when a choice would otherwise have to be
rediscovered by reading the code.

- [1. Telemetry is durable before it is acknowledged](0001-durable-before-acknowledged.md)
- [2. Agent identity comes from the certificate](0002-identity-comes-from-the-certificate.md)
- [3. The protobuf contract is the event model](0003-the-contract-is-the-event-model.md)
- [4. Every process starts from the same skeleton](0004-one-process-skeleton.md)
- [5. The canonical form is for analysis, not for storage](0005-the-canonical-form-is-for-analysis.md)
