package cxclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	"github.com/aws/smithy-go"
)

// Discovery finds the addresses of the HSS tasks.
type Discovery interface {
	HSSAddresses(ctx context.Context) ([]netip.Addr, error)
}

// Resolver resolves a name; *net.Resolver has it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DNSDiscovery finds the HSS tasks by resolving a name, for the compose stack
// and development. Under Cloud Map's MULTIVALUE routing a DNS answer names at
// most eight healthy instances, picked at random per query, so with more HSS
// tasks than that it lists a different subset each time; the client keeps
// connections a single answer leaves out, but use CloudMapDiscovery on AWS.
type DNSDiscovery struct {
	// Resolver is net.DefaultResolver when nil.
	Resolver Resolver
	Name     string
}

// HSSAddresses implements Discovery.
func (d DNSDiscovery) HSSAddresses(ctx context.Context) ([]netip.Addr, error) {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	return r.LookupNetIP(ctx, "ip", d.Name)
}

// CloudMapAPI is the part of the Cloud Map client CloudMapDiscovery uses;
// *servicediscovery.Client has it.
type CloudMapAPI interface {
	DiscoverInstances(context.Context, *servicediscovery.DiscoverInstancesInput, ...func(*servicediscovery.Options)) (*servicediscovery.DiscoverInstancesOutput, error)
}

// cloudMapMaxResults is the most instances one DiscoverInstances call returns,
// well above DefaultMaxPeers.
const cloudMapMaxResults = 1000

// CloudMapDiscovery lists the healthy HSS tasks with Cloud Map's
// DiscoverInstances, which, unlike DNS, returns every instance. It needs
// servicediscovery:DiscoverInstances on the namespace.
type CloudMapDiscovery struct {
	API CloudMapAPI
	// Namespace and Service name the HSS service: rcs.local and hss.
	Namespace, Service string
}

// HSSAddresses implements Discovery.
func (d CloudMapDiscovery) HSSAddresses(ctx context.Context) ([]netip.Addr, error) {
	out, err := d.API.DiscoverInstances(ctx, &servicediscovery.DiscoverInstancesInput{
		NamespaceName: aws.String(d.Namespace),
		ServiceName:   aws.String(d.Service),
		HealthStatus:  types.HealthStatusFilterHealthy,
		MaxResults:    aws.Int32(cloudMapMaxResults),
	})
	if err != nil {
		var api smithy.APIError
		if errors.As(err, &api) {
			return nil, fmt.Errorf("cxclient: discovering the HSS: %s", api.ErrorCode())
		}
		return nil, fmt.Errorf("cxclient: discovering the HSS: %w", err)
	}
	var addrs []netip.Addr
	for _, inst := range out.Instances {
		// ECS registers a task's address under these attributes.
		for _, attr := range []string{"AWS_INSTANCE_IPV4", "AWS_INSTANCE_IPV6"} {
			if a, err := netip.ParseAddr(inst.Attributes[attr]); err == nil {
				addrs = append(addrs, a)
			}
		}
	}
	return addrs, nil
}
