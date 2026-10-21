package scscf

import (
	"context"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// dispatcher is the proxy's Router: it hands each request to the part of
// the S-CSCF that serves it.
//   - REGISTER is the registrar's (TS 24.229 §5.4.1).
//   - SUBSCRIBE for the reg event, initial or in its dialog, is the
//     notifier's (§5.4.2.1).
//   - Any other request outside a dialog goes along the iFC chain, and one
//     inside a dialog along its route (routing.Router).
type dispatcher struct {
	registrar *registrar.Registrar
	notifier  *regevent.Notifier
	router    *routing.Router
	log       *slog.Logger
}

func (d *dispatcher) Route(ctx context.Context, r *proxy.Request) proxy.Decision {
	m := r.Message
	switch {
	case m.Method == "REGISTER":
		return proxy.Decision{Serve: func(ctx context.Context, u *proxy.UAS) {
			d.respond(u, d.registrar.Register(ctx, m, u.Source()))
		}}
	case m.Method == "SUBSCRIBE" && isRegEvent(m):
		return proxy.Decision{Serve: func(ctx context.Context, u *proxy.UAS) {
			res, after := d.notifier.Subscribe(ctx, m)
			d.respond(u, res)
			if after != nil {
				// The NOTIFY the SUBSCRIBE set up goes once the 200 is on
				// its way (RFC 6665 §4.2.1.2), under a context of its own.
				go after(context.WithoutCancel(ctx))
			}
		}}
	case r.Initial():
		return d.router.Initial(ctx, r)
	}
	return d.router.InDialog(ctx, r)
}

// respond hands res to u, logging only that it could not.
func (d *dispatcher) respond(u *proxy.UAS, res *sip.Response) {
	if err := u.Respond(res); err != nil {
		d.log.Warn("scscf: answering a request", slog.String("error", err.Error()))
	}
}

// isRegEvent reports whether req names the reg event package.
func isRegEvent(req *sip.Request) bool {
	ev, err := req.Header.Event()
	return err == nil && ev.Type == "reg"
}
