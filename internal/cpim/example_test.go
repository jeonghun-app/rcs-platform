package cpim_test

import (
	"fmt"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
)

func Example() {
	m := &cpim.Message{}
	_ = m.Add(cpim.CoreNamespace, cpim.HeaderFrom, cpim.Address{Name: "Alice", URI: "sip:alice@example.com"}.String())
	_ = m.Add(cpim.CoreNamespace, cpim.HeaderTo, cpim.Address{URI: "sip:bob@example.com"}.String())
	_ = m.Add(cpim.CoreNamespace, cpim.HeaderDateTime, cpim.FormatDateTime(time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)))
	_ = m.Declare("ext", "urn:example:ext")
	_ = m.Add("urn:example:ext", "Note", "kept as is")
	m.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: "text/plain;charset=UTF-8"}}
	m.Body = content.BodyOf([]byte("Hello"))

	data, err := m.Marshal()
	if err != nil {
		panic(err)
	}
	parsed, err := cpim.Parse(data)
	if err != nil {
		panic(err)
	}
	from, _ := parsed.From()
	note, _ := parsed.Get("urn:example:ext", "Note")
	fmt.Println(from.Name, from.URI)
	fmt.Println(note.Name, "=", note.Value)
	fmt.Println(parsed.ContentType(), string(parsed.Body.Bytes()))
	// Output:
	// Alice sip:alice@example.com
	// ext.Note = kept as is
	// text/plain;charset=UTF-8 Hello
}
