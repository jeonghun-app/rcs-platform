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
	tests := []struct {
		contentType string
		allowed     []string
		want        bool
	}{
		{"text/plain;charset=utf-8", c.FromChatbots, true},
		{"Text/Plain; Charset=UTF-8", c.FromChatbots, true},
		{`text/plain; charset="utf-8"`, c.FromChatbots, true},
		{"text/plain", c.FromChatbots, false},
		{"text/plain;charset=iso-8859-1", c.FromChatbots, false},
		{"text/plain;charset=utf-8;format=flowed", c.FromChatbots, false},
		{"APPLICATION/VND.GSMA.BOTMESSAGE.V1.0+JSON", c.FromChatbots, true},
		{RichCardType + "; charset=utf-8", c.FromChatbots, true},
		{RichCardType + "; version=2", c.FromChatbots, false},
		{ChipListType, c.FromChatbots, false},
		{"text/plain", c.FromSubscribers, true},
		{"text/plain;charset=UTF-8", c.FromSubscribers, true},
		{"text/plain;charset=utf-16", c.FromSubscribers, false},
		{SharedClientDataType, c.FromSubscribers, true},
		{RichCardType, c.FromSubscribers, false},
		{"application/vnd.gsma.rcs-ft-http+xml", c.FromSubscribers, false},
		{"text/plain;charset=utf-8;charset=iso-8859-1", c.FromChatbots, false},
		{"text/", c.FromSubscribers, false},
		{"", c.FromSubscribers, false},
		{"text/plain", []string{"not a type", "text/plain"}, true},
		{"text/plain", nil, false},
		{"application/x-test;v=1", []string{"application/x-test; V=1"}, true},
		{"application/x-test;v=A", []string{"application/x-test;v=a"}, false},
	}
	for _, tc := range tests {
		if got := MatchContentType(tc.contentType, tc.allowed); got != tc.want {
			t.Errorf("MatchContentType(%q, %q) = %v, want %v", tc.contentType, tc.allowed, got, tc.want)
		}
	}
}
