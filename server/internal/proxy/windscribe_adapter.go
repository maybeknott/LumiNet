package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"
)

// WindscribeCallback defines the callback interface for Windscribe session lifecycle events.
type WindscribeCallback struct {
	OnStatusChanged func(status string, details string)
	OnSuccess       func(readiness ProviderRouteReadiness)
	OnFailure       func(errorCode string, err error)
}

// WindscribeAdapter coordinates Windscribe route execution and session management.
type WindscribeAdapter struct{}

// NewWindscribeAdapter creates a new WindscribeAdapter.
func NewWindscribeAdapter() *WindscribeAdapter {
	return &WindscribeAdapter{}
}

// StartSession initiates a Windscribe route observation or session.
func (a *WindscribeAdapter) StartSession(ctx context.Context, cfg RoutingPluginConfig, callback *WindscribeCallback) (<-chan ProviderRouteReadiness, <-chan error) {
	resultChan := make(chan ProviderRouteReadiness, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errChan)

		// Create a child context to manage internal lifetime and propagation
		childCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		if callback == nil {
			callback = &WindscribeCallback{}
		}

		// Wrap callbacks to verify context state before dispatching to external callbacks
		wrappedCallback := &WindscribeCallback{
			OnStatusChanged: func(status string, details string) {
				if childCtx.Err() != nil {
					return
				}
				if callback.OnStatusChanged != nil {
					callback.OnStatusChanged(status, details)
				}
			},
			OnSuccess: func(readiness ProviderRouteReadiness) {
				if childCtx.Err() != nil {
					return
				}
				select {
				case resultChan <- readiness:
				case <-childCtx.Done():
				}
				if callback.OnSuccess != nil {
					callback.OnSuccess(readiness)
				}
			},
			OnFailure: func(errorCode string, err error) {
				if childCtx.Err() != nil {
					return
				}
				select {
				case errChan <- err:
				case <-childCtx.Done():
				}
				if callback.OnFailure != nil {
					callback.OnFailure(errorCode, err)
				}
			},
		}

		// Emit initial transition event
		wrappedCallback.OnStatusChanged("starting", "initiating windscribe adapter session")

		// Validate routing plugin config
		if cfg.PluginID != "windscribe" {
			wrappedCallback.OnFailure("PLUGIN_ROUTE_NOT_READY", errors.New("invalid plugin id for windscribe adapter"))
			return
		}

		// Check for cancellation or continue work
		select {
		case <-childCtx.Done():
			wrappedCallback.OnStatusChanged("cancelled", "session cancelled before connection")
			readiness := ProviderRouteReadiness{
				ProviderID:           "windscribe",
				RouteID:              cfg.RouteID,
				ReadinessState:       "cancelled",
				Status:               "failed",
				ErrorCode:            "PLUGIN_ROUTE_NOT_READY",
				LastTransitionUnixMS: time.Now().UnixMilli(),
				Evidence:             map[string]string{"reason": "context cancelled"},
			}
			select {
			case resultChan <- readiness:
			default:
			}
			select {
			case errChan <- childCtx.Err():
			default:
			}
			return
		case <-time.After(10 * time.Millisecond):
			// Simulated connection logic
		}

		// Check fields
		authMode := cfg.Fields["auth_mode"]
		if authMode == "wsnet_login_required" {
			wrappedCallback.OnFailure("PLUGIN_ROUTE_NOT_READY", errors.New("login required on Android layer"))
			return
		}

		// Proceed to completion if context not cancelled
		select {
		case <-childCtx.Done():
			wrappedCallback.OnStatusChanged("cancelled", "session cancelled during connection")
			readiness := ProviderRouteReadiness{
				ProviderID:           "windscribe",
				RouteID:              cfg.RouteID,
				ReadinessState:       "cancelled",
				Status:               "failed",
				ErrorCode:            "PLUGIN_ROUTE_NOT_READY",
				LastTransitionUnixMS: time.Now().UnixMilli(),
				Evidence:             map[string]string{"reason": "context cancelled"},
			}
			select {
			case resultChan <- readiness:
			default:
			}
			select {
			case errChan <- childCtx.Err():
			default:
			}
			return
		default:
			readiness := ProviderRouteReadiness{
				ProviderID:           "windscribe",
				RouteID:              cfg.RouteID,
				ProtocolMode:         cfg.Fields["mode"],
				RouteBinding:         "profile_backed_vpn_or_proxy",
				ReadinessState:       "probe_passed",
				Status:               "success",
				LastTransitionUnixMS: time.Now().UnixMilli(),
				Evidence:             map[string]string{"session_ref": cfg.CredentialRef},
			}
			wrappedCallback.OnStatusChanged("success", "adapter session established")
			wrappedCallback.OnSuccess(readiness)
		}
	}()

	return resultChan, errChan
}

type WindscribeRouteObserver struct {
	Connectivity ConnectivitySnapshotter
}

func (o WindscribeRouteObserver) Observe(ctx context.Context, cfg RoutingPluginConfig, baseline ConnectivitySnapshot) (ProviderRouteReadiness, error) {
	if o.Connectivity == nil {
		return ProviderRouteReadiness{}, errors.New("connectivity snapshotter is required")
	}
	current, err := o.Connectivity.Snapshot(ctx)
	state := ProviderRouteReadiness{
		ProviderID:           "windscribe",
		RouteID:              cfg.RouteID,
		ProtocolMode:         normalizedProtocolMode(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg),
		RouteBinding:         routeBindingForPlugin(RoutingPluginDescriptor{PluginID: "windscribe", PluginType: "windscribe", RouteType: "plugin"}, cfg),
		RouteStrategy:        normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg),
		ProviderChain:        normalizedProviderChain(cfg),
		LANSharing:           lanSharingEnabled(cfg),
		ReadinessState:       "not_checked",
		Status:               "failed",
		DNSPolicyObserved:    normalizedField(cfg, "dns_policy", "system_or_route_default"),
		InterfaceHint:        current.DefaultInterface,
		Evidence:             map[string]string{},
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}
	if err != nil {
		state.ErrorCode = "TCP_NETWORK_UNREACHABLE"
		return state, err
	}
	state.ExternalVPNObserved = baseline.ExternalIP != "" && current.ExternalIP != "" && baseline.ExternalIP != current.ExternalIP
	state.DNSPolicyObserved = observeDNSPolicy(cfg, baseline, current)
	if state.RouteBinding == "local_proxy_gateway" {
		state.LocalProxyObserved = current.HTTPProxy != "" || current.SOCKSProxy != ""
	}
	state.Evidence["baseline_external_ip_present"] = strconv.FormatBool(baseline.ExternalIP != "")
	state.Evidence["current_external_ip_present"] = strconv.FormatBool(current.ExternalIP != "")
	state.Evidence["dns_resolver_delta"] = strconv.FormatBool(!stringSlicesEqual(baseline.DNSResolvers, current.DNSResolvers))
	if state.ExternalVPNObserved || state.LocalProxyObserved || normalizedProtocolMode(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg) != "external_vpn" {
		state.ReadinessState = "probe_passed"
		state.Status = "success"
		return state, nil
	}
	state.ReadinessState = "degraded"
	state.Status = "failed"
	state.ErrorCode = "PLUGIN_ROUTE_NOT_READY"
	return state, nil
}

func observeDNSPolicy(cfg RoutingPluginConfig, baseline, current ConnectivitySnapshot) string {
	policy := normalizedField(cfg, "dns_policy", "system_or_route_default")
	if policy == "no_dns" {
		return "no_dns"
	}
	if !stringSlicesEqual(baseline.DNSResolvers, current.DNSResolvers) {
		return policy
	}
	return "system_or_route_default"
}

func ProbeLocalHTTPProxy(ctx context.Context, endpoint string, timeout time.Duration) ProviderRouteReadiness {
	start := time.Now()
	state := ProviderRouteReadiness{
		ProviderID:           "windscribe",
		RouteBinding:         "local_proxy_gateway",
		ReadinessState:       "not_checked",
		Status:               "failed",
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		state.ErrorCode = "INPUT_INVALID"
		return state
	}
	parsed, _ := url.Parse(endpoint)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		state.ErrorCode = "PROXY_TIMEOUT"
		return state
	}
	_ = conn.Close()
	state.LocalProxyObserved = true
	state.ReadinessState = "proxy_listening"
	state.Status = "success"
	state.Evidence = map[string]string{"latency_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10)}
	return state
}

type staticConnectivitySnapshotter struct {
	snapshot ConnectivitySnapshot
	err      error
}

func (s staticConnectivitySnapshotter) Snapshot(context.Context) (ConnectivitySnapshot, error) {
	return s.snapshot, s.err
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
