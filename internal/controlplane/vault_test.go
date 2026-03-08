package controlplane

import (
	"encoding/json"
	"testing"
)

func TestParseKeyVersion_Float64(t *testing.T) {
	v, err := parseKeyVersion(float64(3))
	if err != nil || v != 3 {
		t.Errorf("float64: got (%d, %v) want (3, nil)", v, err)
	}
}

func TestParseKeyVersion_Float32(t *testing.T) {
	v, err := parseKeyVersion(float32(5))
	if err != nil || v != 5 {
		t.Errorf("float32: got (%d, %v) want (5, nil)", v, err)
	}
}

func TestParseKeyVersion_Int(t *testing.T) {
	v, err := parseKeyVersion(int(7))
	if err != nil || v != 7 {
		t.Errorf("int: got (%d, %v) want (7, nil)", v, err)
	}
}

func TestParseKeyVersion_Int32(t *testing.T) {
	v, err := parseKeyVersion(int32(2))
	if err != nil || v != 2 {
		t.Errorf("int32: got (%d, %v) want (2, nil)", v, err)
	}
}

func TestParseKeyVersion_Int64(t *testing.T) {
	v, err := parseKeyVersion(int64(10))
	if err != nil || v != 10 {
		t.Errorf("int64: got (%d, %v) want (10, nil)", v, err)
	}
}

func TestParseKeyVersion_JsonNumber(t *testing.T) {
	v, err := parseKeyVersion(json.Number("4"))
	if err != nil || v != 4 {
		t.Errorf("json.Number: got (%d, %v) want (4, nil)", v, err)
	}
}

func TestParseKeyVersion_JsonNumber_Invalid(t *testing.T) {
	_, err := parseKeyVersion(json.Number("notanumber"))
	if err == nil {
		t.Error("expected error for invalid json.Number")
	}
}

func TestParseKeyVersion_Nil(t *testing.T) {
	v, err := parseKeyVersion(nil)
	if err != nil || v != 1 {
		t.Errorf("nil: got (%d, %v) want (1, nil)", v, err)
	}
}

func TestParseKeyVersion_UnknownType(t *testing.T) {
	_, err := parseKeyVersion("a string")
	if err == nil {
		t.Error("expected error for unknown type")
	}
}
