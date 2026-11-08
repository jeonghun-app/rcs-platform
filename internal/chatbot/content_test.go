package chatbot

import (
	"slices"
	"testing"
)

func TestTheBoundsAreThoseOfTheADR(t *testing.T) {
	if MaxContentBytes != 253_952 || MaxDisplayNameBytes != 128 || MaxOutOfServiceTextBytes != 512 {
		t.Errorf("bounds %d, %d, %d", MaxContentBytes, MaxDisplayNameBytes, MaxOutOfServiceTextBytes)
	}
}

func TestTheDefaultContentTypesAreThoseOfRCC07AndFreshEachTime(t *testing.T) {
	c := DefaultContentTypes()
	if !slices.Equal(c.FromChatbots, []string{"text/plain;charset=utf-8", "application/vnd.gsma.botmessage.v1.0+json"}) ||
		c.ChipList != "application/vnd.gsma.botsuggestion.v1.0+json" ||
		!slices.Equal(c.FromSubscribers, []string{"text/plain",
			"application/vnd.gsma.botsuggestion.response.v1.0+json", "application/vnd.gsma.botsharedclientdata.v1.0+json"}) {
		t.Errorf("DefaultContentTypes = %+v", c)
	}
	c.FromChatbots[0], c.FromSubscribers[0] = "x/y", "x/y"
	if d := DefaultContentTypes(); d.FromChatbots[0] == "x/y" || d.FromSubscribers[0] == "x/y" {
		t.Error("changing one copy changed the defaults")
	}
}

func TestAContentTypeMatchesItsEntryWhateverTheCaseAndAUTF8Charset(t *testing.T) {
	c := DefaultContentTypes()
	chatbotText, subscriberText := c.FromChatbots[0], c.FromSubscribers[0]
	tests := []struct {
		contentType string
		allowed     []string
		want        string // the entry matched, "" for none
	}{
		{"text/plain;charset=utf-8", c.FromChatbots, chatbotText},
		{"Text/Plain; Charset=UTF-8", c.FromChatbots, chatbotText},
		{`text/plain; charset="utf-8"`, c.FromChatbots, chatbotText},
		{"text/plain", c.FromChatbots, ""},
		{"text/plain;charset=iso-8859-1", c.FromChatbots, ""},
		{"text/plain;charset=utf-8;format=flowed", c.FromChatbots, ""},
		{"APPLICATION/VND.GSMA.BOTMESSAGE.V1.0+JSON", c.FromChatbots, RichCardType},
		{RichCardType + "; charset=utf-8", c.FromChatbots, RichCardType},
		{RichCardType + "; version=2", c.FromChatbots, ""},
		{ChipListType, c.FromChatbots, ""},
		{"text/plain", c.FromSubscribers, subscriberText},
		{"text/plain;charset=UTF-8", c.FromSubscribers, subscriberText},
		{"text/plain;charset=utf-16", c.FromSubscribers, ""},
		{SharedClientDataType, c.FromSubscribers, SharedClientDataType},
		{RichCardType, c.FromSubscribers, ""},
		{"application/vnd.gsma.rcs-ft-http+xml", c.FromSubscribers, ""},
		{"text/plain;charset=utf-8;charset=iso-8859-1", c.FromChatbots, ""},
		{"text/", c.FromSubscribers, ""},
		{"", c.FromSubscribers, ""},
		{"text/plain", []string{"not a type", "text/plain"}, "text/plain"},
		{"text/plain", nil, ""},
		{"application/x-test;v=1", []string{"application/x-test; V=1"}, "application/x-test; V=1"},
		{"application/x-test;v=A", []string{"application/x-test;v=a"}, ""},
		// Control characters mime.ParseMediaType would trim, and RFC 2231
		// parameter names, match nothing.
		{"\r\ntext/plain", c.FromSubscribers, ""},
		{"text/plain\r\n", c.FromSubscribers, ""},
		{"text/plain;charset=utf-8\r\n\r\n", c.FromChatbots, ""},
		{"text/plain;\r\n charset=utf-8", c.FromChatbots, ""},
		{"text/plain;\tcharset=utf-8", c.FromChatbots, ""},
		{"text/plain\x00", c.FromSubscribers, ""},
		{"text/plain\x7f", c.FromSubscribers, ""},
		{"text/plain;charset*=utf-8''utf-8", c.FromChatbots, ""},
		{"text/plain;charset*0=utf;charset*1=-8", c.FromChatbots, ""},
		{"text/plain;CHARSET*=utf-8''utf-8", c.FromSubscribers, ""},
		// A "*" inside a quoted value is no RFC 2231 mark.
		{`application/x-test;v="a;*=b";w=1`, []string{`application/x-test;v="a;*=b";w=1`}, `application/x-test;v="a;*=b";w=1`},
		{`application/x-test;v="a\";*=b"`, []string{`application/x-test;v="a\";*=b"`}, `application/x-test;v="a\";*=b"`},
	}
	for _, tc := range tests {
		got, ok := MatchContentType(tc.contentType, tc.allowed)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("MatchContentType(%q, %q) = %q, %v; want %q", tc.contentType, tc.allowed, got, ok, tc.want)
		}
	}
}
