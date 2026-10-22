package sip

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Errors are logged, and header values carry identities, so no error may contain
// input bytes. Two tests hold that: one reads the package source and checks every
// reason is a string literal, so a later edit cannot build one from input; the
// other drives every error path with a marker value and checks it never comes
// back.

func TestEveryErrorReasonIsAStringLiteral(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var reason ast.Expr
			switch n := n.(type) {
			case *ast.CallExpr:
				fn, ok := n.Fun.(*ast.Ident)
				switch {
				case !ok:
				case fn.Name == "syntaxError" && len(n.Args) == 1:
					reason = n.Args[0]
				case fn.Name == "headerError" && len(n.Args) == 2:
					reason = n.Args[1]
				}
			case *ast.CompositeLit:
				if typ, ok := n.Type.(*ast.Ident); ok && typ.Name == "ParseError" {
					for _, el := range n.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok && kv.Key.(*ast.Ident).Name == "Reason" {
							reason = kv.Value
						}
					}
				}
			}
			if reason == nil {
				return true
			}
			checked++
			// The helpers themselves pass their parameter on.
			if id, ok := reason.(*ast.Ident); ok && id.Name == "reason" {
				return true
			}
			if lit, ok := reason.(*ast.BasicLit); !ok || lit.Kind != token.STRING {
				t.Errorf("%s: error reason is not a string literal", fset.Position(reason.Pos()))
			}
			return true
		})
	}
	if checked < 50 {
		t.Errorf("checked only %d error reasons; is the test still finding them?", checked)
	}
}

func TestErrorsNeverContainInput(t *testing.T) {
	const marker = "Zq7Secret"
	const number = "+15550100001"
	bad := marker + number
	var errs []error
	add := func(err error) {
		t.Helper()
		if err == nil {
			t.Errorf("case %d did not fail", len(errs))
		}
		errs = append(errs, err)
	}
	parse := func(msg string) {
		_, err := ParseMessage([]byte(msg))
		add(err)
	}
	stream := func(msg string) {
		_, err := NewReader(bufio.NewReader(strings.NewReader(msg)), Limits{}).ReadMessage()
		add(err)
	}

	// Framing and the start line.
	parse(lines("OPTIONS sip:"+bad+" x SIP/2.0", "l: 0"))
	parse(lines("OPTIONS <sip:"+bad+"@example.com> SIP/2.0", "l: 0"))
	parse(lines(bad+"( sip:a@example.com SIP/2.0", "l: 0"))
	parse(lines("OPTIONS sip:a@example.com SIP/"+bad, "l: 0"))
	parse(lines("SIP/2.0 2"+bad, "l: 0"))
	parse(lines("SIP/2.0 200 "+bad+"\x00", "l: 0"))
	parse(lines("OPTIONS sip:a@example.com SIP/2.0", bad+" no colon"))
	parse(lines("OPTIONS sip:a@example.com SIP/2.0", bad+" name: x"))
	parse(lines("OPTIONS sip:a@example.com SIP/2.0", "X: "+bad+"\x01"))
	parse(lines("OPTIONS sip:a@example.com SIP/2.0", "Content-Length: "+bad))
	parse("OPTIONS sip:a@example.com SIP/2.0\r\nX: " + bad + "\r\n")
	stream(lines("OPTIONS sip:a@example.com SIP/2.0", "X: "+bad))
	stream("OPTIONS sip:a@example.com SIP/2.0\n" + bad + "\n\n")

	// Every value parser, through its accessor.
	h := func(name, value string) *Header { return headerWith(t, name, value) }
	for _, get := range []func() error{
		func() error { _, err := h("Via", "SIP/2.0/UDP "+bad+"_x").Via(); return err },
		func() error { _, err := h("Via", "SIP/2.0/UDP h;received="+bad).Via(); return err },
		func() error { _, err := h("From", `"`+bad).From(); return err },
		func() error { _, err := h("To", "<sip:"+bad+"@example.com> "+bad).To(); return err },
		func() error { _, err := h("Call-ID", bad+" "+bad).CallID(); return err },
		func() error { _, err := h("CSeq", "1 "+bad+" x").CSeq(); return err },
		func() error { _, err := h("Max-Forwards", bad).MaxForwards(); return err },
		func() error { _, err := h("Max-Breadth", bad).MaxBreadth(); return err },
		func() error { _, err := h("Contact", "<sip:a@b>;"+bad+"=").Contact(); return err },
		func() error {
			cs, _ := h("Contact", "<sip:a@b>;expires="+bad).Contact()
			_, _, err := cs[0].Expires()
			return err
		},
		func() error { _, err := h("Route", "sip:"+bad+"@example.com").Route(); return err },
		func() error { _, err := h("Expires", bad).Expires(); return err },
		func() error { _, err := h("Require", bad+" x").Require(); return err },
		func() error { _, err := h("Content-Type", bad).ContentType(); return err },
		func() error { _, err := h("WWW-Authenticate", "Digest "+bad).WWWAuthenticate(); return err },
		func() error { _, err := h("Authorization", `Digest username="`+bad).Authorization(); return err },
		func() error { _, err := h("P-Called-Party-ID", "sip:"+bad+"@example.com").PCalledPartyID(); return err },
		func() error { _, err := h("P-Visited-Network-ID", bad+" x").PVisitedNetworkID(); return err },
		func() error { _, err := h("P-Charging-Vector", bad+"=1").PChargingVector(); return err },
		func() error { _, err := h("Accept-Contact", bad).AcceptContact(); return err },
		func() error { _, err := h("Event", bad+" x").Event(); return err },
		func() error { _, err := h("Subscription-State", "active;expires="+bad).SubscriptionState(); return err },
		func() error { _, err := h("Session-Expires", "1;refresher="+bad).SessionExpires(); return err },
		func() error { _, err := h("Min-SE", bad).MinSE(); return err },
		func() error { _, err := h("Reason", "SIP;cause="+bad).Reason(); return err },
		func() error { _, err := ParseURI("tel:" + bad); return err },
		func() error { _, err := ParseURI("sip:a@" + bad + "_"); return err },
		func() error { _, err := ParseVia(bad); return err },
		func() error { return h("Route", "<sip:a.example.com;lr>").ReplaceFirstElement("Route", bad+","+bad) },
		func() error { var x Header; return x.Add("X", bad+"\x00") },
		func() error {
			req := mustParse(t, strings.Replace(basicInvite, "CSeq: 1 INVITE", "CSeq: 1 "+bad, 1))
			return req.Validate()
		},
		func() error {
			req := mustParse(t, strings.Replace(basicInvite, "To: Bob <sip:bob@example.com>", "To: <sip:"+bad, 1)).(*Request)
			_, err := NewResponse(req, 486, "", "t")
			return err
		},
	} {
		add(get())
	}

	for i, err := range errs {
		if err == nil {
			continue
		}
		if msg := err.Error(); strings.Contains(msg, marker) || strings.Contains(msg, "15550100001") {
			t.Errorf("case %d: error %q contains input", i, msg)
		}
	}
}
