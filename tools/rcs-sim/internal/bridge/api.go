package bridge

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket"
)

// maxRequestBody bounds a request's JSON body.
const maxRequestBody = 64 << 10

// pingInterval is how often an event stream is pinged; a stream that has
// not answered the previous ping by the next one is closed, so that a
// vanished client does not hold its slot.
const pingInterval = 30 * time.Second

func (b *Bridge) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/endpoints/{name}", b.putEndpoint)
	mux.HandleFunc("POST /v1/endpoints/{name}/messages", b.sendMessage)
	mux.HandleFunc("POST /v1/endpoints/{name}/imdn", b.sendIMDN)
	mux.HandleFunc("GET /v1/events", b.events)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		// Every request needs the token, the event stream's handshake and
		// unknown paths too, so that without it nothing is learnt.
		if !b.authorized(r) {
			rec.Header().Set("WWW-Authenticate", `Bearer realm="rcs-bridge"`)
			writeJSON(rec, http.StatusUnauthorized, errorBody{"a bearer token is needed"})
		} else {
			mux.ServeHTTP(rec, r)
		}
		// The pattern, never the path: the path holds the endpoint's name.
		b.log.Debug("request", slog.String("method", r.Method), slog.String("route", r.Pattern),
			slog.Int("status", rec.status), slog.String("took", time.Since(start).String()))
	})
}

// authorized reports whether r carries the token, compared in constant
// time (secret.Key.Equal).
func (b *Bridge) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return secret.NewString(strings.TrimLeft(token, " ")).Equal(b.cfg.Token)
}

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads r's JSON body into v. An empty body leaves v as it is.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return errTooBig
		}
		return errors.New("the body is not the JSON object expected")
	}
	if dec.More() {
		return errors.New("the body is not one JSON object")
	}
	return nil
}

var errTooBig = errors.New("the body is larger than 64 KiB")

func badBody(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, errTooBig) {
		status = http.StatusRequestEntityTooLarge
	}
	writeJSON(w, status, errorBody{err.Error()})
}

// putEndpoint is PUT /v1/endpoints/{name}: the endpoint is provisioned the
// first time, and registered or unregistered as "online" says (true when
// absent). It answers once that is done or has failed: "registered" is the
// result.
func (b *Bridge) putEndpoint(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		writeJSON(w, http.StatusBadRequest, errorBody{"the endpoint name is not 1 to 64 letters, digits, '.', '_', '~' or '-'"})
		return
	}
	var req struct {
		Online *bool `json:"online"`
	}
	if err := decode(w, r, &req); err != nil {
		badBody(w, err)
		return
	}
	online := req.Online == nil || *req.Online
	ctx, cancel := b.opContext()
	defer cancel()
	e, created, err := b.endpoint(ctx, name)
	switch {
	case errors.Is(err, errFull):
		writeJSON(w, http.StatusConflict, errorBody{err.Error()})
		return
	case errors.Is(err, ErrClosed):
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"rcs-bridge is shutting down"})
		return
	case err != nil:
		reason := safeerr.Reason(err).Error()
		b.log.Warn("provisioning failed", pii.Identity("endpoint", name), slog.String("reason", reason))
		writeJSON(w, http.StatusBadGateway, errorBody{"provisioning the subscriber failed: " + reason})
		return
	}
	e.setOnline(ctx, online)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, e.view())
}

// sent is the answer to a send: the Message-ID and the final SIP status.
type sent struct {
	MessageID string `json:"message_id"`
	SIPStatus int    `json:"sip_status"`
}

// sendMessage is POST /v1/endpoints/{name}/messages.
func (b *Bridge) sendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To          string   `json:"to"`
		ContentType string   `json:"content_type"`
		Body        string   `json:"body"`
		MessageID   string   `json:"message_id"`
		IMDN        []string `json:"imdn"`
	}
	if err := decode(w, r, &req); err != nil {
		badBody(w, err)
		return
	}
	e, ok := b.sender(w, r)
	if !ok {
		return
	}
	m := outgoing{contentType: req.ContentType, body: req.Body, messageID: req.MessageID}
	if m.contentType == "" {
		m.contentType = defaultContentType
	}
	var err error
	if m.target, err = b.target(req.To); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if !validContentType(m.contentType) {
		writeJSON(w, http.StatusBadRequest, errorBody{"content_type is not a media type"})
		return
	}
	for _, v := range req.IMDN {
		switch v {
		case "delivery":
			m.asked |= imdn.PositiveDelivery
		case "display":
			m.asked |= imdn.Display
		default:
			writeJSON(w, http.StatusBadRequest, errorBody{`imdn holds a value other than "delivery" and "display"`})
			return
		}
	}
	switch {
	case m.messageID == "":
		if m.messageID, err = imdn.NewMessageID(b.cfg.Rand); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody{"no Message-ID could be made"})
			return
		}
	case !validMessageID(m.messageID):
		writeJSON(w, http.StatusBadRequest, errorBody{"message_id is not a token of at most 128 characters"})
		return
	}
	cpimBody, err := e.cpimMessage(m)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"the message cannot be written as CPIM"})
		return
	}
	line := e.currentLine()
	if line == nil {
		writeJSON(w, http.StatusConflict, errorBody{errOffline.Error()})
		return
	}
	ctx, cancel := b.opContext()
	defer cancel()
	status, err := line.Send(ctx, m.target, cpimBody)
	if err != nil {
		reason := safeerr.Reason(err).Error()
		b.log.Warn("message not sent", pii.Identity("endpoint", e.name), slog.String("reason", reason))
		writeJSON(w, http.StatusBadGateway, errorBody{"the MESSAGE got no answer: " + reason})
		return
	}
	b.log.Info("message sent", pii.Identity("endpoint", e.name), slog.Int("sip_status", status))
	writeJSON(w, http.StatusOK, sent{MessageID: m.messageID, SIPStatus: status})
}

// sendIMDN is POST /v1/endpoints/{name}/imdn: a display notification about
// a message the endpoint received, to its sender. Delivery notifications
// the bridge sends itself.
func (b *Bridge) sendIMDN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To        string `json:"to"`
		MessageID string `json:"message_id"`
		Status    string `json:"status"`
	}
	if err := decode(w, r, &req); err != nil {
		badBody(w, err)
		return
	}
	e, ok := b.sender(w, r)
	if !ok {
		return
	}
	if req.Status != string(imdn.Displayed) {
		writeJSON(w, http.StatusBadRequest, errorBody{`status must be "displayed": the bridge sends delivery notifications itself`})
		return
	}
	to, err := b.target(req.To)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	rec, ok := e.received.get(req.MessageID)
	if ok && !sameUser(rec.from, to) {
		cf, err := rec.msg.From()
		u, perr := sip.ParseURI(cf.URI)
		ok = err == nil && perr == nil && sameUser(u, to)
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, errorBody{"the endpoint has received no message with that message_id from that sender"})
		return
	}
	if !rec.request.Dispositions.Wants(imdn.DisplayNotification, imdn.Displayed) {
		// RFC 5438 §7.2.1: nobody sends a notification that was not asked
		// for, and rcs-as would refuse it.
		writeJSON(w, http.StatusConflict, errorBody{"the sender did not ask for a display notification"})
		return
	}
	ctx, cancel := b.opContext()
	defer cancel()
	status, err := e.notify(ctx, nil, rec, imdn.DisplayNotification, imdn.Displayed)
	switch {
	case errors.Is(err, errOffline):
		writeJSON(w, http.StatusConflict, errorBody{err.Error()})
		return
	case err != nil:
		reason := safeerr.Reason(err).Error()
		b.log.Warn("display notification not sent", pii.Identity("endpoint", e.name), slog.String("reason", reason))
		writeJSON(w, http.StatusBadGateway, errorBody{"the notification got no answer: " + reason})
		return
	}
	b.log.Info("display notification sent", pii.Identity("endpoint", e.name), slog.Int("sip_status", status))
	writeJSON(w, http.StatusOK, sent{MessageID: req.MessageID, SIPStatus: status})
}

// sender is the endpoint of r's path, or it answers 400 or 404.
func (b *Bridge) sender(w http.ResponseWriter, r *http.Request) (*endpoint, bool) {
	name := r.PathValue("name")
	if !validName(name) {
		writeJSON(w, http.StatusBadRequest, errorBody{"the endpoint name is not 1 to 64 letters, digits, '.', '_', '~' or '-'"})
		return nil, false
	}
	e, err := b.lookup(name)
	switch {
	case errors.Is(err, ErrClosed):
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"rcs-bridge is shutting down"})
		return nil, false
	case e == nil:
		writeJSON(w, http.StatusNotFound, errorBody{"no such endpoint: create it with PUT first"})
		return nil, false
	}
	return e, true
}

// target is what "to" names: one of the bridge's endpoints, by its SIP
// identity, or a sip:, sips: or global tel: URI as it is.
func (b *Bridge) target(to string) (sip.URI, error) {
	if to == "" {
		return sip.URI{}, errors.New("to is needed")
	}
	if !strings.Contains(to, ":") {
		e, _ := b.lookup(to)
		if e == nil {
			return sip.URI{}, errors.New("to names no endpoint of this bridge")
		}
		return e.sub.IMPU, nil
	}
	u, err := sip.ParseURI(to)
	switch {
	case err != nil:
		return sip.URI{}, errors.New("to is not a SIP or tel URI")
	case u.IsSIP() && u.Host != "":
		return u, nil
	case u.Scheme == "tel" && u.IsGlobalNumber():
		return u, nil
	}
	return sip.URI{}, errors.New("to must be an endpoint name, a sip: URI or a global tel: URI")
}

// events is GET /v1/events: a WebSocket of JSON text frames, one per event
// of any endpoint, from the moment it opens. What happens while no stream
// is open is not kept.
func (b *Bridge) events(w http.ResponseWriter, r *http.Request) {
	s, ok := b.hub.subscribe()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"no more event streams can be opened"})
		return
	}
	defer b.hub.unsubscribe(s)
	conn, err := websocket.Upgrade(w, r, websocket.Options{})
	if err != nil {
		var he *websocket.HandshakeError
		if errors.As(err, &he) {
			writeJSON(w, he.Status, errorBody{he.Reason})
		}
		return
	}
	defer conn.Shutdown()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			// The client has nothing to say; reading answers its pings
			// and takes its Close.
			if _, _, err := conn.Read(); err != nil {
				return
			}
		}
	}()
	tick := make(chan struct{}, 1)
	var timer transaction.Timer
	arm := func() {
		timer = b.cfg.Clock.AfterFunc(pingInterval, func() {
			select {
			case tick <- struct{}{}:
			default:
			}
		})
	}
	arm()
	defer func() { timer.Stop() }()
	var pongs int64
	pinged := false
	for {
		select {
		case ev := <-s.events:
			if conn.WriteText(ev) != nil {
				return
			}
		case <-tick:
			if pinged && conn.Pongs() == pongs {
				return
			}
			pongs, pinged = conn.Pongs(), true
			if conn.Ping(nil) != nil {
				return
			}
			arm()
		case <-readDone:
			return
		case <-s.gone:
			switch s.closing {
			case closedBehind:
				_ = conn.Close(websocket.StatusPolicy, "events not read fast enough")
			default:
				// What was published before the shutdown still goes.
				for drained := false; !drained; {
					select {
					case ev := <-s.events:
						if conn.WriteText(ev) != nil {
							return
						}
					default:
						drained = true
					}
				}
				_ = conn.Close(websocket.StatusGoingAway, "rcs-bridge is shutting down")
			}
			<-readDone
			return
		}
	}
}

// statusRecorder keeps the status a handler wrote, for the request log,
// and lets the event stream take the connection over.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController and websocket.Upgrade reach the
// connection.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
