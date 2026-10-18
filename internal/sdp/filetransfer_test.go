package sdp

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestFileOfferExposesEveryFileTransferAttribute(t *testing.T) {
	m := &mustParse(t, fileOffer).Media[0]

	sel, err := m.FileSelector()
	want := FileSelector{
		Name: `beach photo".jpg`,
		Type: "image/jpeg",
		Size: 48213,
		Hashes: []FileHash{{
			Algorithm: "sha-1",
			Value:     "72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E",
		}},
	}
	if err != nil || !reflect.DeepEqual(sel, want) {
		t.Errorf("FileSelector = %+v, %v\nwant %+v", sel, err, want)
	}
	if id, err := m.FileTransferID(); err != nil || id != "vBnG916bdberum2fFEABR4f" {
		t.Errorf("FileTransferID = %q, %v", id, err)
	}
	if d, err := m.FileDisposition(); err != nil || d != "render" {
		t.Errorf("FileDisposition = %q, %v", d, err)
	}
	wantDate := FileDate{Creation: "Mon, 12 Oct 2026 09:30:00 +0000", Modification: "Tue, 13 Oct 2026 10:00:00 +0000"}
	if fd, err := m.FileDate(); err != nil || fd != wantDate {
		t.Errorf("FileDate = %+v, %v", fd, err)
	}
	if icon, err := m.FileIcon(); err != nil || icon != "cid:icon1@example.com" {
		t.Errorf("FileIcon = %q, %v", icon, err)
	}
	if r, err := m.FileRange(); err != nil || r != (FileRange{Start: 1, Stop: 48213}) {
		t.Errorf("FileRange = %+v, %v", r, err)
	}
	if n, err := m.MaxSize(); err != nil || n != 10485760 {
		t.Errorf("MaxSize = %d, %v", n, err)
	}
}

func TestFileSelectorFormsTheGrammarAllows(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  FileSelector
	}{
		{"no value at all", "", FileSelector{Size: -1}},
		{"name only", `name:"a b\c.txt"`, FileSelector{Name: `a b\c.txt`, Size: -1}},
		{"upper-case keys", `NAME:"x" SIZE:0`, FileSelector{Name: "x", Size: 0}},
		{"type with a quoted parameter", `type:text/plain;charset="utf 8" size:3`, FileSelector{Type: `text/plain;charset="utf 8"`, Size: 3}},
		{"two hashes", "hash:sha-1:AB hash:sha-256:cd:EF", FileSelector{Size: -1, Hashes: []FileHash{{"sha-1", "AB"}, {"sha-256", "cd:EF"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Media{Attributes: Attributes{{Name: "file-selector", Value: tt.value}}}
			got, err := m.FileSelector()
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestMalformedFileTransferAttributesAreRejected(t *testing.T) {
	get := map[string]func(m *Media) error{
		"file-selector":    func(m *Media) error { _, err := m.FileSelector(); return err },
		"file-transfer-id": func(m *Media) error { _, err := m.FileTransferID(); return err },
		"file-disposition": func(m *Media) error { _, err := m.FileDisposition(); return err },
		"file-date":        func(m *Media) error { _, err := m.FileDate(); return err },
		"file-icon":        func(m *Media) error { _, err := m.FileIcon(); return err },
		"file-range":       func(m *Media) error { _, err := m.FileRange(); return err },
	}
	tests := []struct {
		attr, value, wantErr string
	}{
		{"file-selector", `name:"unterminated`, "unterminated quoted string"},
		{"file-selector", `name:"a"  size:1`, "empty entry"},
		{"file-selector", `size:1 `, "empty entry"},
		{"file-selector", `name:x`, "name must be a non-empty quoted string"},
		{"file-selector", `name:""`, "name must be a non-empty quoted string"},
		{"file-selector", `name:"a"b"`, "unterminated quoted string"},
		{"file-selector", `name:"100%"`, "malformed percent-encoding"},
		{"file-selector", `name:"a" name:"b"`, "more than one name selector"},
		{"file-selector", `size:`, "has no value"},
		{"file-selector", `size`, "has no value"},
		{"file-selector", `size:-1`, "size must be a number of bytes"},
		{"file-selector", `type:image`, "type must be a media type"},
		{"file-selector", `type:image/*`, "type must be a media type"},
		{"file-selector", `hash:sha-1`, "hash must be"},
		{"file-selector", `hash:sha-1:ABC`, "hash must be"},
		{"file-selector", `hash:sha-1:AB-CD`, "hash must be"},
		{"file-selector", `hash:sha-1:GG`, "hash must be"},
		{"file-selector", `colour:blue`, "unknown selector"},
		{"file-transfer-id", "a b", "is not a token"},
		{"file-disposition", "re/nder", "is not a token"},
		{"file-date", `creation:"x" creation:"y"`, "more than one creation date"},
		{"file-date", `creation:x`, "a date must be a non-empty quoted string"},
		{"file-date", `creation:""`, "a date must be a non-empty quoted string"},
		{"file-date", `birthday:"x"`, "unknown date parameter"},
		{"file-date", `read:"x`, "unterminated quoted string"},
		{"file-icon", "http://example.com/icon.png", "is not a cid: URL"},
		{"file-icon", "cid:", "is not a cid: URL"},
		{"file-range", "0-10", "is not <start>-<stop>"},
		{"file-range", "10-9", "is not <start>-<stop>"},
		{"file-range", "10", "is not <start>-<stop>"},
		{"file-range", "1-x", "is not <start>-<stop>"},
	}
	for _, tt := range tests {
		t.Run(tt.attr+" "+tt.value, func(t *testing.T) {
			m := &Media{Attributes: Attributes{{Name: tt.attr, Value: tt.value}}}
			if err := get[tt.attr](m); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
	for attr, fn := range get {
		if err := fn(&Media{}); !errors.Is(err, ErrNoAttribute) {
			t.Errorf("%s on a line without it = %v, want ErrNoAttribute", attr, err)
		}
	}
}

func TestOpenEndedFileRangeHasStopMinusOne(t *testing.T) {
	m := Media{Attributes: Attributes{{Name: "file-range", Value: "1025-*"}}}
	if r, err := m.FileRange(); err != nil || r != (FileRange{Start: 1025, Stop: -1}) {
		t.Errorf("FileRange = %+v, %v", r, err)
	}
}

func TestFileDateReadsEachDateKind(t *testing.T) {
	m := Media{Attributes: Attributes{{Name: "file-date", Value: `read:"r" Creation:"c"`}}}
	if fd, err := m.FileDate(); err != nil || fd != (FileDate{Creation: "c", Read: "r"}) {
		t.Errorf("FileDate = %+v, %v", fd, err)
	}
}
