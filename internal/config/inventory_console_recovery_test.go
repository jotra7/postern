package config_test

import (
	"testing"
)

// A host that declares console_recovery: true alongside its console URL must
// parse with InventoryHost.ConsoleRecovery set: this is the inventory-side
// half of the console-recovery acknowledgement that lets Compile produce a
// Policy with no always_allow_iface (see compile_test.go in internal/bundle
// for the compiled-policy half).
func TestConfig_ParseInventory_MapsConsoleRecoveryField(t *testing.T) {
	data := inventoryFixture(t,
		`    console: "https://provider.example/instances/web-01/console"`,
		"    console: \"https://provider.example/instances/web-01/console\"\n    console_recovery: true",
	)
	inv := mustParseInventory(t, data)
	h, err := inv.Host("web-01")
	if err != nil {
		t.Fatalf("Host(web-01): %v", err)
	}
	if !h.ConsoleRecovery {
		t.Error("ConsoleRecovery = false, want true")
	}
	if h.Console != "https://provider.example/instances/web-01/console" {
		t.Errorf("Console = %q, want the fixture's console URL", h.Console)
	}

	// web-02 declares neither field: both must stay at zero.
	h2, err := inv.Host("web-02")
	if err != nil {
		t.Fatalf("Host(web-02): %v", err)
	}
	if h2.ConsoleRecovery {
		t.Error("web-02 ConsoleRecovery = true, want false (not declared)")
	}
}
