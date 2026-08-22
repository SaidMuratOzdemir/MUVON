package main

import "testing"

// The precedence has to be unambiguous: whoever configured the host wins over
// the settings table, and the settings table wins over the compiled default.
// Getting this backwards would either ignore the operator's own flags or
// re-introduce the bug where the setting does nothing.
func TestSettingOrFlag(t *testing.T) {
	const envName = "MUVON_TEST_SIZING_ENV"

	t.Run("setting applies when nothing was set at the host", func(t *testing.T) {
		if got := settingOrFlag("no-such-flag", envName, 10000, 42); got != 42 {
			t.Fatalf("got %d, want the settings value 42", got)
		}
	})

	t.Run("environment variable wins over the setting", func(t *testing.T) {
		t.Setenv(envName, "1234")
		if got := settingOrFlag("no-such-flag", envName, 1234, 42); got != 1234 {
			t.Fatalf("got %d, want the host value 1234", got)
		}
	})

	t.Run("unset setting keeps the default", func(t *testing.T) {
		if got := settingOrFlag("no-such-flag", envName, 10000, 0); got != 10000 {
			t.Fatalf("got %d, want the default 10000", got)
		}
	})

	t.Run("negative setting is ignored", func(t *testing.T) {
		if got := settingOrFlag("no-such-flag", envName, 10000, -5); got != 10000 {
			t.Fatalf("got %d, want the default 10000", got)
		}
	})
}
