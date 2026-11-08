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
