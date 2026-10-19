package rcsas

import (
	"bytes"
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

var devEnv = map[string]string{
	"RCS_ENV":               "dev",
	"RCSAS_MSRP_HOST":       "10.0.0.7",
	"RCSAS_STORE":           "memory",
	"RCSAS_CONFERENCE_HOST": "conf.ims.example.net",
}

func with(base map[string]string, kv ...string) map[string]string {
	m := maps.Clone(base)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func configure(env map[string]string) (Config, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix(EnvPrefix), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

func TestTheDefaultsAreTheDocumentedOnes(t *testing.T) {
	c, err := configure(with(devEnv, "RCSAS_STORE", ""))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Messaging
	if m := c.Messaging; m.QueueSenderShare != 8 || m.MaxQueueMessages != 1000 || m.MaxQueueBytes != 16<<20 || m.AnswerTimeout != 32*time.Second ||
		m.RetryInterval != time.Minute || m.MaxRetryInterval != time.Hour || len(m.TrustedRoutes) != 0 {
		t.Fatalf("messaging %+v", m)
	}
	if c.Store != StoreDynamoDB || c.DynamoDB.Table != "messages" || c.MSRPListenAddr != ":2855" || m.MSRPPort != 2855 ||
		m.MSRPHost != "10.0.0.7" || m.StoreTTL != 7*24*time.Hour || m.SentTTL != 8*24*time.Hour || m.PagerLimit != 1300 ||
		m.MaxMessageSize != 256<<10 || m.SenderRate.PerMinute != 60 || m.MSRP.KeepAliveInterval != 240*time.Second {
		t.Fatalf("config %+v", c)
	}
}

func TestEverySettingIsRead(t *testing.T) {
	c, err := configure(with(devEnv,
		"RCSAS_STORE", "dynamodb", "RCSAS_DYNAMODB_TABLE", "rcs-messages", "RCSAS_DYNAMODB_ENDPOINT", "http://ddb:8000",
		"RCSAS_MSRP_LISTEN_ADDR", ":12855", "RCSAS_SELF_URIS", "sip:rcs-as.ims.example.net, sip:rcs-as2.ims.example.net",
		"RCSAS_IMDN_INTERMEDIARIES", "sip:mstore.example.org", "RCSAS_MAX_MESSAGE_SIZE", "65536", "RCSAS_PAGER_LIMIT", "1000",
		"RCSAS_STORE_TTL", "48h", "RCSAS_SENT_TTL", "72h", "RCSAS_SENDER_RATE", "10", "RCSAS_SENDER_BURST", "5",
		"RCSAS_NOTIFICATION_RATE", "100", "RCSAS_NOTIFICATION_BURST", "50", "RCSAS_DELIVERY_TIMEOUT", "10s",
		"RCSAS_INVITE_TIMEOUT", "1m", "RCSAS_STORE_TIMEOUT", "2s", "RCSAS_SWEEP_INTERVAL", "30s", "RCSAS_MSRP_KEEPALIVE", "100s",
		"RCSAS_TRUSTED_ROUTES", "sip:as.ims.example.net;lr", "RCSAS_QUEUE_SENDER_SHARE", "4", "RCSAS_MAX_QUEUE_MESSAGES", "50", "RCSAS_MAX_QUEUE_BYTES", "1048576",
		"RCSAS_ANSWER_TIMEOUT", "20s", "RCSAS_RETRY_INTERVAL", "30s", "RCSAS_MAX_RETRY_INTERVAL", "10m"))
	if err != nil {
		t.Fatal(err)
	}
	m := c.Messaging
	if c.DynamoDB.Table != "rcs-messages" || c.DynamoDB.Endpoint != "http://ddb:8000" || m.MSRPPort != 12855 ||
		len(m.Self) != 2 || m.Intermediaries[0] != "sip:mstore.example.org" || m.MaxMessageSize != 65536 || m.PagerLimit != 1000 ||
		m.StoreTTL != 48*time.Hour || m.SentTTL != 72*time.Hour || m.SenderRate.Burst != 5 || m.NotificationRate.PerMinute != 100 ||
		m.DeliveryTimeout != 10*time.Second || m.InviteTimeout != time.Minute || m.StoreTimeout != 2*time.Second ||
		m.SweepInterval != 30*time.Second || m.MSRP.KeepAliveInterval != 100*time.Second ||
		m.TrustedRoutes[0] != "sip:as.ims.example.net;lr" || m.QueueSenderShare != 4 || m.MaxQueueMessages != 50 || m.MaxQueueBytes != 1<<20 ||
		m.AnswerTimeout != 20*time.Second || m.RetryInterval != 30*time.Second || m.MaxRetryInterval != 10*time.Minute {
		t.Fatalf("config %+v", c)
	}
}

func TestInvalidSettingsAreAllReported(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no host":         {with(devEnv, "RCSAS_MSRP_HOST", ""), "RCSAS_MSRP_HOST"},
		"bad listen":      {with(devEnv, "RCSAS_MSRP_LISTEN_ADDR", "2855"), "RCSAS_MSRP_LISTEN_ADDR"},
		"no port":         {with(devEnv, "RCSAS_MSRP_LISTEN_ADDR", ":http"), "RCSAS_MSRP_LISTEN_ADDR"},
		"unknown store":   {with(devEnv, "RCSAS_STORE", "redis"), "RCSAS_STORE"},
		"zero size":       {with(devEnv, "RCSAS_MAX_MESSAGE_SIZE", "0"), "RCSAS_MAX_MESSAGE_SIZE"},
		"zero pager":      {with(devEnv, "RCSAS_PAGER_LIMIT", "0"), "RCSAS_PAGER_LIMIT"},
		"zero ttl":        {with(devEnv, "RCSAS_STORE_TTL", "0s"), "RCSAS_STORE_TTL"},
		"zero sweep":      {with(devEnv, "RCSAS_SWEEP_INTERVAL", "0s"), "RCSAS_SWEEP_INTERVAL"},
		"short sent ttl":  {with(devEnv, "RCSAS_SENT_TTL", "1h"), "RCSAS_SENT_TTL"},
		"pager over size": {with(devEnv, "RCSAS_MAX_MESSAGE_SIZE", "1000"), "RCSAS_PAGER_LIMIT"},
		"beyond an item":  {with(devEnv, "RCSAS_STORE", "dynamodb", "RCSAS_MAX_MESSAGE_SIZE", "400000"), "RCSAS_MAX_MESSAGE_SIZE"},
		"not a duration":  {with(devEnv, "RCSAS_STORE_TTL", "7d"), "RCSAS_STORE_TTL"},
		"negative rate":   {with(devEnv, "RCSAS_SENDER_RATE", "-1"), "RCSAS_SENDER_RATE"},
		"zero queue":      {with(devEnv, "RCSAS_MAX_QUEUE_MESSAGES", "0"), "RCSAS_MAX_QUEUE_MESSAGES"},
		"share too small": {with(devEnv, "RCSAS_QUEUE_SENDER_SHARE", "128"), "RCSAS_QUEUE_SENDER_SHARE"},
		"zero share":      {with(devEnv, "RCSAS_QUEUE_SENDER_SHARE", "0"), "RCSAS_QUEUE_SENDER_SHARE"},
		"queue below one": {with(devEnv, "RCSAS_MAX_QUEUE_BYTES", "1000"), "RCSAS_MAX_QUEUE_BYTES"},
		"zero answer":     {with(devEnv, "RCSAS_ANSWER_TIMEOUT", "0s"), "RCSAS_ANSWER_TIMEOUT"},
		"retry backwards": {with(devEnv, "RCSAS_RETRY_INTERVAL", "2h"), "RCSAS_MAX_RETRY_INTERVAL"},
		"negative burst":  {with(devEnv, "RCSAS_NOTIFICATION_BURST", "-1"), "RCSAS_NOTIFICATION_BURST"},
	} {
		_, err := configure(c.env)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestProductionRefusesTheMemoryStoreAndALocalEndpoint(t *testing.T) {
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	env := with(devEnv, "RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32), "RCSAS_DYNAMODB_ENDPOINT", "http://ddb:8000")
	status := runtime.Run(ctx, runtime.Service[Config]{
		Name: "rcs-as", EnvPrefix: EnvPrefix, Configure: Configure,
		Run: func(context.Context, *runtime.Runtime, Config) error { return nil },
	}, runtime.Process{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Stdout: &out})
	if status != runtime.ExitFailure {
		t.Fatalf("status = %d", status)
	}
	for _, want := range []string{"RCSAS_STORE=memory", "RCSAS_DYNAMODB_ENDPOINT"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("refusal does not mention %q:\n%s", want, out.String())
		}
	}
}

func TestARateOfZeroTurnsTheLimitOff(t *testing.T) {
	c, err := configure(with(devEnv, "RCSAS_SENDER_RATE", "0", "RCSAS_NOTIFICATION_RATE", "0", "RCSAS_NOTIFICATION_BURST", "0"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Messaging.SenderRate.PerMinute >= 0 || c.Messaging.NotificationRate.PerMinute >= 0 {
		t.Fatalf("rates %+v %+v", c.Messaging.SenderRate, c.Messaging.NotificationRate)
	}
}

func TestTheGroupSettingsAreRead(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	g := c.Group
	if c.GroupsTable != "groupchats" || g.ConferenceHost != "conf.ims.example.net" || g.MaxParticipants != 100 ||
		g.IdleTTL != 30*24*time.Hour || g.SenderRate.PerMinute != 60 || g.FanoutRate.Burst != 1000 || g.AddRate.PerMinute != 30 ||
		g.CreateRate.Burst != 10 {
		t.Fatalf("defaults %+v", c.Group)
	}
	c, err = configure(with(devEnv, "RCSAS_GROUPCHATS_TABLE", "rcs-groups", "RCSAS_GROUP_MAX_PARTICIPANTS", "20",
		"RCSAS_GROUP_IDLE_TTL", "240h", "RCSAS_GROUP_SENDER_RATE", "10", "RCSAS_GROUP_SENDER_BURST", "3",
		"RCSAS_GROUP_FANOUT_RATE", "0", "RCSAS_GROUP_ADD_RATE", "5", "RCSAS_GROUP_ADD_BURST", "19",
		"RCSAS_GROUP_CREATE_RATE", "1", "RCSAS_GROUP_CREATE_BURST", "1"))
	if err != nil {
		t.Fatal(err)
	}
	g = c.Group
	if c.GroupsTable != "rcs-groups" || g.MaxParticipants != 20 || g.IdleTTL != 240*time.Hour || g.SenderRate.Burst != 3 ||
		g.FanoutRate.PerMinute >= 0 || g.AddRate.Burst != 19 || g.CreateRate.PerMinute != 1 {
		t.Fatalf("settings %+v", c.Group)
	}
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no conference host":    {with(devEnv, "RCSAS_CONFERENCE_HOST", ""), "RCSAS_CONFERENCE_HOST"},
		"no participants":       {with(devEnv, "RCSAS_GROUP_MAX_PARTICIPANTS", "0"), "RCSAS_GROUP_MAX_PARTICIPANTS"},
		"too many participants": {with(devEnv, "RCSAS_GROUP_MAX_PARTICIPANTS", "201", "RCSAS_GROUP_FANOUT_BURST", "1000"), "RCSAS_GROUP_MAX_PARTICIPANTS"},
		"no idle time":          {with(devEnv, "RCSAS_GROUP_IDLE_TTL", "0s"), "RCSAS_GROUP_IDLE_TTL"},
		"a small fan-out":       {with(devEnv, "RCSAS_GROUP_FANOUT_BURST", "50"), "RCSAS_GROUP_FANOUT_BURST"},
		"a negative rate":       {with(devEnv, "RCSAS_GROUP_ADD_RATE", "-1"), "RCSAS_GROUP_ADD_RATE"},
		"a negative burst":      {with(devEnv, "RCSAS_GROUP_CREATE_BURST", "-1"), "RCSAS_GROUP_CREATE_BURST"},
	} {
		if _, err := configure(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
