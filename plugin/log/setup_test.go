package log

import (
	"net"
	"reflect"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/response"
)

func TestLogParse(t *testing.T) {
	tests := []struct {
		inputLogRules    string
		shouldErr        bool
		expectedLogRules []Rule
	}{
		{`log`, false, []Rule{{
			NameScope: ".",
			Format:    DefaultLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org`, false, []Rule{{
			NameScope: "example.org.",
			Format:    DefaultLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org. {common}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org {combined}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CombinedLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org.
		log example.net {combined}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    DefaultLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}, {
			NameScope: "example.net.",
			Format:    CombinedLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org {host}
			  log example.org {when}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    "{host}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}, {
			NameScope: "example.org.",
			Format:    "{when}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org example.net`, false, []Rule{{
			NameScope: "example.org.",
			Format:    DefaultLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}, {
			NameScope: "example.net.",
			Format:    DefaultLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org example.net {host}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    "{host}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}, {
			NameScope: "example.net.",
			Format:    "{host}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org example.net {when} {
			class denial
		}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    "{when}",
			Class:     map[response.Class]struct{}{response.Denial: {}},
		}, {
			NameScope: "example.net.",
			Format:    "{when}",
			Class:     map[response.Class]struct{}{response.Denial: {}},
		}}},

		{`log example.org {
				class all
			}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org {
			class denial
		}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.Denial: {}},
		}}},
		{`log {
			class denial
		}`, false, []Rule{{
			NameScope: ".",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.Denial: {}},
		}}},
		{`log {
			class denial error
		}`, false, []Rule{{
			NameScope: ".",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.Denial: {}, response.Error: {}},
		}}},
		{`log {
			class denial
			class error
		}`, false, []Rule{{
			NameScope: ".",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.Denial: {}, response.Error: {}},
		}}},
		{`log {
			class abracadabra
		}`, true, []Rule{}},
		{`log {
			class
		}`, true, []Rule{}},
		{`log {
			unknown
		}`, true, []Rule{}},
		{`log example.org "{combined} {/forward/upstream}"`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CombinedLogFormat + " {/forward/upstream}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org "{common} {/forward/upstream}"`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CommonLogFormat + " {/forward/upstream}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org "{when} {combined} {/forward/upstream}"`, false, []Rule{{
			NameScope: "example.org.",
			Format:    "{when} " + CombinedLogFormat + " {/forward/upstream}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log example.org "{when} {common} {/forward/upstream}"`, false, []Rule{{
			NameScope: "example.org.",
			Format:    "{when} " + CommonLogFormat + " {/forward/upstream}",
			Class:     map[response.Class]struct{}{response.All: {}},
		}}},
		{`log {
			except_source 10.1.0.0/16 2001:db8::/32
		}`, false, []Rule{{
			NameScope: ".",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.All: {}},
			DenyNets:  mustCIDRs(t, "10.1.0.0/16", "2001:db8::/32"),
		}}},
		{`log example.org {
			class success denial
			except_source 10.1.0.0/16
		}`, false, []Rule{{
			NameScope: "example.org.",
			Format:    CommonLogFormat,
			Class:     map[response.Class]struct{}{response.Success: {}, response.Denial: {}},
			DenyNets:  mustCIDRs(t, "10.1.0.0/16"),
		}}},
		{`log {
			except_source 10.0.0.0
		}`, true, []Rule{}},
		{`log {
			except_source no-cidr
		}`, true, []Rule{}},
	}
	for i, test := range tests {
		c := caddy.NewTestController("dns", test.inputLogRules)
		actualLogRules, err := logParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d with input '%s' didn't error, but it should have", i, test.inputLogRules)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d with input '%s' errored, but it shouldn't have; got '%v'",
				i, test.inputLogRules, err)
		}
		if len(actualLogRules) != len(test.expectedLogRules) {
			t.Fatalf("Test %d expected %d no of Log rules, but got %d",
				i, len(test.expectedLogRules), len(actualLogRules))
		}
		for j, actualLogRule := range actualLogRules {
			if actualLogRule.NameScope != test.expectedLogRules[j].NameScope {
				t.Errorf("Test %d expected %dth LogRule NameScope for '%s' to be  %s  , but got %s",
					i, j, test.inputLogRules, test.expectedLogRules[j].NameScope, actualLogRule.NameScope)
			}

			if actualLogRule.Format != test.expectedLogRules[j].Format {
				t.Errorf("Test %d expected %dth LogRule Format for '%s' to be  %s  , but got %s",
					i, j, test.inputLogRules, test.expectedLogRules[j].Format, actualLogRule.Format)
			}

			if !reflect.DeepEqual(actualLogRule.Class, test.expectedLogRules[j].Class) {
				t.Errorf("Test %d expected %dth LogRule Class to be  %v  , but got %v",
					i, j, test.expectedLogRules[j].Class, actualLogRule.Class)
			}
			if !reflect.DeepEqual(actualLogRule.DenyNets, test.expectedLogRules[j].DenyNets) {
				t.Errorf("Test %d expected %dth LogRule DenyNets to be  %v  , but got %v",
					i, j, test.expectedLogRules[j].DenyNets, actualLogRule.DenyNets)
			}
		}
	}
}

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()

	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("invalid cidr %q in test: %v", cidr, err)
		}
		nets = append(nets, n)
	}

	return nets
}
