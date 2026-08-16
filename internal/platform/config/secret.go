package config

import "log/slog"

const redacted = "[redacted]"

type Secret string

func (s Secret) Reveal() string { return string(s) }

func (s Secret) Empty() bool { return len(s) == 0 }

func (s Secret) String() string { return redacted }

func (s Secret) GoString() string { return redacted }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (s Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
