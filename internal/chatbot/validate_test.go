package chatbot

import (
	"errors"
	"strings"
	"testing"
)

func TestValidContentIsAccepted(t *testing.T) {
	deep := strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth)
	long := "[" + strings.Repeat("0,", MaxJSONArray-1) + "0]"
	tests := map[string]struct{ contentType, body string }{
		"text with tab, CR, LF": {"text/plain;charset=utf-8", "line one\r\n\tline two é 😀"},
		"text that is no JSON":  {"text/plain", `{"a":1,"a":2}`},
		"empty text":            {"text/plain", ""},
		"rich card":             {RichCardType, `{"message":{"generalPurposeCard":{"content":{"title":"t"}}},"n":[1e308,-0.5]}`},
		"JSON at the depth":     {"application/json", deep},
		"array at the bound":    {SuggestionResponseType, long},
		"keys in two cases":     {ChipListType, `{"text":1,"Text":2}`},
		"parameters and case":   {"Application/Vnd.GSMA.Botmessage.v1.0+JSON; charset=utf-8", `"s"`},
	}
	for name, tc := range tests {
		if err := ValidateContent(tc.contentType, []byte(tc.body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInvalidContentIsRefusedWithItsReason(t *testing.T) {
	deep := strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1)
	long := "[" + strings.Repeat("0,", MaxJSONArray) + "0]"
	tests := map[string]struct{ contentType, body, reason string }{
		"not UTF-8":        {"text/plain", "secret \xff", "not UTF-8"},
		"NUL":              {"text/plain", "secret \x00", "a control character other than tab, CR or LF"},
		"escape character": {RichCardType, "{\"secret\":\"\x1b[2J\"}", "a control character other than tab, CR or LF"},
		"two values":       {RichCardType, `{"secret":1} {}`, "data after the JSON value"},
		"trailing data":    {RichCardType, `{"secret":1}x`, "data after the JSON value"},
		"duplicate key":    {RichCardType, `{"secret":1,"secret":2}`, "a duplicate key"},
		"escaped dup":      {RichCardType, `{"secret":1,"\u0073ecret":2}`, "a duplicate key"},
		"too deep":         {"application/json", deep, "nested deeper than 32"},
		"long array":       {"application/json", long, "an array of more than 1000 elements"},
		"infinite":         {RichCardType, `{"secret":1e400}`, "a number beyond the range of a float64"},
		"minus infinite":   {RichCardType, `[-1e400]`, "a number beyond the range of a float64"},
		"empty JSON":       {RichCardType, "", "not JSON"},
		"invalid JSON":     {RichCardType, `{"secret" 1}`, "not JSON"},
		"unclosed":         {RichCardType, `{"secret":[1,2`, "not JSON"},
	}
	for name, tc := range tests {
		err := ValidateContent(tc.contentType, []byte(tc.body))
		if !errors.Is(err, ErrInvalidContent) || reasonOf(err) != tc.reason {
			t.Errorf("%s: %v, want %q", name, err, tc.reason)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error %q repeats the content", name, err)
		}
	}
}
