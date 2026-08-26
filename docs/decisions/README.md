# Architecture decisions

Each record states what forced the decision, what was decided, and what the
decision costs. They are written when a choice would otherwise have to be
rediscovered by reading the code.

- [1. Telemetry is durable before it is acknowledged](0001-durable-before-acknowledged.md)
- [2. Agent identity comes from the certificate](0002-identity-comes-from-the-certificate.md)
- [3. The protobuf contract is the event model](0003-the-contract-is-the-event-model.md)
- [4. Every process starts from the same skeleton](0004-one-process-skeleton.md)
- [5. The canonical form is for analysis, not for storage](0005-the-canonical-form-is-for-analysis.md)
- [6. A detection rule addresses the contract](0006-a-rule-addresses-the-contract.md)
- [7. A rule file is not the rule](0007-a-rule-file-is-not-the-rule.md)
- [8. A ruleset is named by what is in it](0008-a-ruleset-is-named-by-what-is-in-it.md)
- [9. An absent field answers no question](0009-an-absent-field-answers-no-question.md)
- [10. A rule carries the cases it was written for](0010-a-rule-carries-the-cases-it-was-written-for.md)
- [11. A detection is not an alert](0011-a-detection-is-not-an-alert.md)
- [12. Storage is owned per workload, and an alert is not a detection](0012-storage-is-owned-per-workload.md)
