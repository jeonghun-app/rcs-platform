// Package maap is the maap service, the half of the Chatbot Platform outside
// the SIP trust domain (ADR 0009 §1): the chatbot registry, the chatbot API,
// webhook delivery, aliases and policy limits. rcs-as hosts the chatbot PSI
// and builds every SIP request; maap reaches rcs-as only, over internal
// HTTP (ADR 0007 §3–§5).
//
// This package holds the settings and their start checks, and the request
// plumbing every maap listener shares: bearer tokens per caller, compared
// as SHA-256 digests in constant time and decided before the body is read;
// strict JSON envelopes through chatbot.DecodeEnvelope; the cap on decodes
// in flight that bounds a task's memory; and the refusal of control
// characters in envelope strings bound for a header or a log.
// docs/maap.md describes the service and its settings.
package maap
