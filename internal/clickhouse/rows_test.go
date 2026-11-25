package clickhouse

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/inventorystore"
)

// Gives every field of the struct row points at a value no other field has.
func distinct(t *testing.T, row any) {
	t.Helper()
	fields := reflect.ValueOf(row).Elem()
	for index := range fields.NumField() {
		field := fields.Field(index)
		switch {
		case field.Kind() == reflect.String:
			field.SetString(fmt.Sprintf("field-%d", index))
		case field.Kind() == reflect.Uint32 || field.Kind() == reflect.Uint64:
			field.SetUint(uint64(index + 1))
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String:
			field.Set(reflect.ValueOf([]string{fmt.Sprintf("field-%d", index)}))
		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint32:
			field.Set(reflect.ValueOf([]uint32{uint32(index + 1)}))
		case field.Type() == reflect.TypeOf(time.Time{}):
			field.Set(reflect.ValueOf(time.Unix(int64(index+1), 0).UTC()))
		default:
			t.Fatalf("%s is a %s, which this test cannot give a value of its own", fields.Type().Field(index).Name, field.Type())
		}
	}
}

// A row is read back through the same columns in the same order it is written
// through, so every field lands where it came from.
func readsBack(t *testing.T, written, read any, values, pointers []any) {
	t.Helper()
	if len(pointers) != len(values) {
		t.Fatalf("a row is read back through %d columns and written through %d", len(pointers), len(values))
	}
	for index := range values {
		reflect.ValueOf(pointers[index]).Elem().Set(reflect.ValueOf(values[index]))
	}
	if held := reflect.ValueOf(read).Elem().Interface(); !reflect.DeepEqual(held, written) {
		t.Errorf("a row was written as\n%+v\nand read back as\n%+v", written, held)
	}
}

func TestEveryStoredRowIsReadBackIntoTheFieldsItWasWrittenFrom(t *testing.T) {
	var item, readItem inventorystore.Row
	distinct(t, &item)
	readsBack(t, item, &readItem, inventoryValues(item), inventoryPointers(&readItem))

	var advisory, readAdvisory advisorystore.AdvisoryRow
	distinct(t, &advisory)
	readsBack(t, advisory, &readAdvisory, advisoryValues(advisory), advisoryPointers(&readAdvisory))

	var affected, readAffected advisorystore.AffectedRow
	distinct(t, &affected)
	readsBack(t, affected, &readAffected, affectedValues(affected), affectedPointers(&readAffected))
}
