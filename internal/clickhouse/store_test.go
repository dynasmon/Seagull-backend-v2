package clickhouse

import (
	"testing"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

func TestTheAnalyticalStoreUsesTLSByDefault(t *testing.T) {
	parser := config.New(func(key string) (string, bool) {
		if key == "SEAGULL_EVENT_STORE_ADDRESS" {
			return "clickhouse.example:9440", true
		}
		return "", false
	})

	loaded := LoadConfig("SEAGULL_EVENT_STORE", parser)

	if err := parser.Err(); err != nil {
		t.Fatal(err)
	}
	if !loaded.TLS {
		t.Fatal("the analytical store defaulted to plaintext")
	}
}

func TestAnalyticalStoreTLSOptionsCannotBeIgnored(t *testing.T) {
	if _, err := (Config{ServerName: "clickhouse.example"}).tls(); err == nil {
		t.Fatal("a server name was accepted with analytical store tls off")
	}
}
