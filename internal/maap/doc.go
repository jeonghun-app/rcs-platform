// Package maap is the maap service, the half of the Chatbot Platform outside
// the SIP trust domain (ADR 0009 §1): the chatbot registry, the chatbot API,
// webhook delivery, aliases and policy limits. rcs-as hosts the chatbot PSI
// and builds every SIP request; maap reaches rcs-as only, over internal
// HTTP (ADR 0007 §3–§5).
//
// This package holds the settings and their start checks: the alias host
// apart from the IMS and chatbot domains, the operator's tokens, and the
// cap on request bodies decoded at once. docs/maap.md describes the service
// and its settings.
package maap
