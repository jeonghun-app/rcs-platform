# rcs-as chatbot API: callers and scopes

The operations are specified in [rcs-as.yaml](rcs-as.yaml);
[ADR 0009](../adr/0009-maap-chatbot-platform.md) §4, §6 and §7 describe the
API. This page is the scope table ADR 0007 §3 asks for next to the API.
`rcs-as` serves it on `RCSAS_CHATBOT_LISTEN_ADDR`, with `maap`'s tokens in
`RCSAS_MAAP_TOKEN` and `RCSAS_MAAP_TOKEN_NEXT` ([rcs-as](../rcs-as.md#chatbot-api)).

| Caller | Allowed |
|---|---|
| `maap` → `rcs-as` | sends and notifications from a sender in the chatbot range, to subscribers only |

`maap` has a token of its own toward `rcs-as`, two live at a time (current
and next), never `hss`'s operator token (ADR 0009 §7). `rcs-as` refuses a
sender outside the chatbot range and a recipient inside it, whatever the
token, so a compromised `maap` can impersonate chatbots and no one else.
