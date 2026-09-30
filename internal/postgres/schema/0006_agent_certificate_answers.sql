-- What a renewal asked with, kept beside the certificate that answered it: the
-- certificate the agent presented and the digest of its request. A renewal whose
-- answer was lost is asked again with both, and that is how it is told from
-- anybody else presenting the certificate it replaced. A certificate an operator
-- had signed answered no renewal and keeps both empty.
ALTER TABLE agent_certificates
    ADD COLUMN presented_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_sha256        TEXT NOT NULL DEFAULT '';
