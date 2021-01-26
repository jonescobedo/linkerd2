package util

import (
	"encoding/binary"
	"fmt"

	"github.com/linkerd/linkerd2/controller/api/util"
	netPb "github.com/linkerd/linkerd2/controller/gen/common/net"
	"github.com/linkerd/linkerd2/pkg/k8s"
	pb "github.com/linkerd/linkerd2/viz/metrics-api/gen/viz"
	"github.com/linkerd/linkerd2/viz/pkg/api"
)

// ValidTapDestinations specifies resource types allowed as a tap destination:
// - destination resource on an outbound 'to' query
var ValidTapDestinations = []string{
	k8s.CronJob,
	k8s.DaemonSet,
	k8s.Deployment,
	k8s.Job,
	k8s.Namespace,
	k8s.Pod,
	k8s.ReplicaSet,
	k8s.ReplicationController,
	k8s.Service,
	k8s.StatefulSet,
}

// TapRequestParams contains parameters that are used to build a
// TapByResourceRequest.
type TapRequestParams struct {
	Resource      string
	Namespace     string
	ToResource    string
	ToNamespace   string
	MaxRps        float32
	Scheme        string
	Method        string
	Authority     string
	Path          string
	Extract       bool
	LabelSelector string
}

// BuildTapByResourceRequest builds a Public API TapByResourceRequest from a
// TapRequestParams.
func BuildTapByResourceRequest(params TapRequestParams) (*pb.TapByResourceRequest, error) {
	target, err := util.BuildResource(params.Namespace, params.Resource)
	if err != nil {
		return nil, fmt.Errorf("target resource invalid: %s", err)
	}
	if !contains(api.ValidTargets, target.Type) {
		return nil, fmt.Errorf("unsupported resource type [%s]", target.Type)
	}

	matches := []*pb.TapByResourceRequest_Match{}

	if params.ToResource != "" {
		destination, err := util.BuildResource(params.ToNamespace, params.ToResource)
		if err != nil {
			return nil, fmt.Errorf("destination resource invalid: %s", err)
		}
		if !contains(ValidTapDestinations, destination.Type) {
			return nil, fmt.Errorf("unsupported resource type [%s]", destination.Type)
		}

		match := pb.TapByResourceRequest_Match{
			Match: &pb.TapByResourceRequest_Match_Destinations{
				Destinations: &pb.ResourceSelection{
					Resource: destination,
				},
			},
		}
		matches = append(matches, &match)
	}

	if params.Scheme != "" {
		match := buildMatchHTTP(&pb.TapByResourceRequest_Match_Http{
			Match: &pb.TapByResourceRequest_Match_Http_Scheme{Scheme: params.Scheme},
		})
		matches = append(matches, &match)
	}
	if params.Method != "" {
		match := buildMatchHTTP(&pb.TapByResourceRequest_Match_Http{
			Match: &pb.TapByResourceRequest_Match_Http_Method{Method: params.Method},
		})
		matches = append(matches, &match)
	}
	if params.Authority != "" {
		match := buildMatchHTTP(&pb.TapByResourceRequest_Match_Http{
			Match: &pb.TapByResourceRequest_Match_Http_Authority{Authority: params.Authority},
		})
		matches = append(matches, &match)
	}
	if params.Path != "" {
		match := buildMatchHTTP(&pb.TapByResourceRequest_Match_Http{
			Match: &pb.TapByResourceRequest_Match_Http_Path{Path: params.Path},
		})
		matches = append(matches, &match)
	}

	extract := &pb.TapByResourceRequest_Extract{}
	if params.Extract {
		extract = buildExtractHTTP(&pb.TapByResourceRequest_Extract_Http{
			Extract: &pb.TapByResourceRequest_Extract_Http_Headers_{
				Headers: &pb.TapByResourceRequest_Extract_Http_Headers{},
			},
		})
	}

	return &pb.TapByResourceRequest{
		Target: &pb.ResourceSelection{
			Resource:      target,
			LabelSelector: params.LabelSelector,
		},
		MaxRps: params.MaxRps,
		Match: &pb.TapByResourceRequest_Match{
			Match: &pb.TapByResourceRequest_Match_All{
				All: &pb.TapByResourceRequest_Match_Seq{
					Matches: matches,
				},
			},
		},
		Extract: extract,
	}, nil
}

func buildMatchHTTP(match *pb.TapByResourceRequest_Match_Http) pb.TapByResourceRequest_Match {
	return pb.TapByResourceRequest_Match{
		Match: &pb.TapByResourceRequest_Match_Http_{
			Http: match,
		},
	}
}

func buildExtractHTTP(extract *pb.TapByResourceRequest_Extract_Http) *pb.TapByResourceRequest_Extract {
	return &pb.TapByResourceRequest_Extract{
		Extract: &pb.TapByResourceRequest_Extract_Http_{
			Http: extract,
		},
	}
}

func contains(list []string, s string) bool {
	for _, elem := range list {
		if s == elem {
			return true
		}
	}
	return false
}

// CreateTapEvent generates tap events for use in tests
func CreateTapEvent(eventHTTP *pb.TapEvent_Http, dstMeta map[string]string, proxyDirection pb.TapEvent_ProxyDirection) *pb.TapEvent {
	event := &pb.TapEvent{
		ProxyDirection: proxyDirection,
		Source: &netPb.TcpAddress{
			Ip: &netPb.IPAddress{
				Ip: &netPb.IPAddress_Ipv4{
					Ipv4: uint32(1),
				},
			},
		},
		Destination: &netPb.TcpAddress{
			Ip: &netPb.IPAddress{
				Ip: &netPb.IPAddress_Ipv6{
					Ipv6: &netPb.IPv6{
						// All nodes address: https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
						First: binary.BigEndian.Uint64([]byte{0xff, 0x01, 0, 0, 0, 0, 0, 0}),
						Last:  binary.BigEndian.Uint64([]byte{0, 0, 0, 0, 0, 0, 0, 0x01}),
					},
				},
			},
		},
		Event: &pb.TapEvent_Http_{
			Http: eventHTTP,
		},
		DestinationMeta: &pb.TapEvent_EndpointMeta{
			Labels: dstMeta,
		},
	}
	return event
}
