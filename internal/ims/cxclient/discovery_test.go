package cxclient

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	"github.com/aws/smithy-go"
)

type fakeCloudMap struct {
	in  *servicediscovery.DiscoverInstancesInput
	out *servicediscovery.DiscoverInstancesOutput
	err error
}

func (f *fakeCloudMap) DiscoverInstances(_ context.Context, in *servicediscovery.DiscoverInstancesInput, _ ...func(*servicediscovery.Options)) (*servicediscovery.DiscoverInstancesOutput, error) {
	f.in = in
	return f.out, f.err
}

func TestCloudMapDiscoveryListsEveryHealthyTask(t *testing.T) {
	var insts []types.HttpInstanceSummary
	for i := 1; i <= 12; i++ {
		insts = append(insts, types.HttpInstanceSummary{Attributes: map[string]string{"AWS_INSTANCE_IPV4": "192.0.2." + itoa(i)}})
	}
	insts = append(insts, types.HttpInstanceSummary{Attributes: map[string]string{"AWS_INSTANCE_IPV6": "2001:db8::1"}},
		types.HttpInstanceSummary{Attributes: map[string]string{"other": "x"}},
		// A dual-stack task is one peer, by its IPv4 address.
		types.HttpInstanceSummary{Attributes: map[string]string{"AWS_INSTANCE_IPV4": "192.0.2.99", "AWS_INSTANCE_IPV6": "2001:db8::99"}})
	f := &fakeCloudMap{out: &servicediscovery.DiscoverInstancesOutput{Instances: insts}}
	d := CloudMapDiscovery{API: f, Namespace: "rcs.local", Service: "hss"}
	got, err := d.HSSAddresses(context.Background())
	if err != nil || len(got) != 14 || !slices.Contains(got, netip.MustParseAddr("2001:db8::1")) ||
		!slices.Contains(got, netip.MustParseAddr("192.0.2.99")) || slices.Contains(got, netip.MustParseAddr("2001:db8::99")) {
		t.Fatalf("addresses %v, %v", got, err)
	}
	if aws.ToString(f.in.NamespaceName) != "rcs.local" || aws.ToString(f.in.ServiceName) != "hss" || f.in.HealthStatus != types.HealthStatusFilterHealthy {
		t.Errorf("request %+v", f.in)
	}
	f.err = &smithy.GenericAPIError{Code: "NamespaceNotFound", Message: "no namespace rcs.local"}
	if _, err := d.HSSAddresses(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		t.Errorf("error %v", err)
	}
}
