package chatbot

// Bounds of ADR 0009 §5 and §7.
const (
	// MaxContentBytes bounds a chatbot's content, chip list included:
	// 248 KiB, above the payload size RCC.07 v13.0 §3.6.10.1 suggests for
	// JSON, and 8 KiB below rcs-as's smallest RCSAS_MAX_MESSAGE_SIZE with
	// the chatbot API on, room for the CPIM rcs-as writes around it.
	MaxContentBytes = 248 << 10
	// MaxDisplayNameBytes bounds a chatbot's display name before escaping.
	MaxDisplayNameBytes = 128
	// MaxOutOfServiceTextBytes bounds the text/plain a suspended chatbot's
	// subscribers get (§11).
	MaxOutOfServiceTextBytes = 512
)

// The content types of RCC.07 v13.0 §3.6.10.2.
const (
	RichCardType           = "application/vnd.gsma.botmessage.v1.0+json"
	ChipListType           = "application/vnd.gsma.botsuggestion.v1.0+json"
	SuggestionResponseType = "application/vnd.gsma.botsuggestion.response.v1.0+json"
	SharedClientDataType   = "application/vnd.gsma.botsharedclientdata.v1.0+json"
)

// ContentTypes are the content types a service accepts each way; anything
// else is 415 (ADR 0009 §5). They are operator configuration: a service
// starts from [DefaultContentTypes] and its settings replace them.
type ContentTypes struct {
	// FromChatbots are the types of a chatbot's message, each of which may
	// carry one chip list of type ChipList as the second part of a
	// multipart CPIM (§3.6.10.1). An empty ChipList allows none.
	FromChatbots []string
	ChipList     string
	// FromSubscribers are the types a subscriber may send a chatbot.
	FromSubscribers []string
}

// DefaultContentTypes returns the content types of RCC.07 v13.0 §3.6.10.2,
// newly allocated so that a service may change its copy.
func DefaultContentTypes() ContentTypes {
	return ContentTypes{
		FromChatbots:    []string{"text/plain;charset=utf-8", RichCardType},
		ChipList:        ChipListType,
		FromSubscribers: []string{"text/plain", SuggestionResponseType, SharedClientDataType},
	}
}
