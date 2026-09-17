package runner

import (
	"strings"
	"testing"
)

// TestMergePrecedence pins the rule that ARCHITECTURE.md and the implementation
// plan both leave as "a documented precedence rule" without ever stating it.
// The runner cannot be written without deciding, so the decision lives here and
// is enforced by a test.
func TestMergePrecedence(t *testing.T) {
	base := Environment{"PATH": "/usr/bin", "HOME": "/home/dev", "NODE_ENV": "development"}
	profile := Environment{"NODE_ENV": "production", "DEMO_SECRET": "value"}

	got := base.Merge(profile)

	if got["NODE_ENV"] != "production" {
		t.Errorf("profile must win: NODE_ENV = %q, want %q", got["NODE_ENV"], "production")
	}
	if got["HOME"] != "/home/dev" {
		t.Errorf("unrelated parent variable must pass through: HOME = %q", got["HOME"])
	}
	if got["PATH"] != "/usr/bin" {
		t.Errorf("PATH must pass through untouched: %q", got["PATH"])
	}
	if got["DEMO_SECRET"] != "value" {
		t.Errorf("new profile variable missing: %q", got["DEMO_SECRET"])
	}
	if _, ok := base["DEMO_SECRET"]; ok {
		t.Error("Merge mutated the base environment")
	}
}

// TestMergeEmptyValueIsNotEmpty checks that an empty value means "set to empty"
// rather than "delete". Collapsing those two would make it impossible to run a
// child with, say, an intentionally blank token.
func TestMergeEmptyValueIsNotEmpty(t *testing.T) {
	base := Environment{"FEATURE_FLAG": "on"}
	got := base.Merge(Environment{"FEATURE_FLAG": ""})

	v, ok := got["FEATURE_FLAG"]
	if !ok {
		t.Fatal("variable was deleted instead of set to empty")
	}
	if v != "" {
		t.Fatalf("value = %q, want empty", v)
	}
}

// TestShellShimDetection covers the Windows .cmd/.bat classification on every
// platform.
//
// On Windows, `npm`, `yarn`, `tsc` and friends resolve to .cmd shims that
// CreateProcess cannot execute — cmd.exe is the only way to run a batch file.
// Detecting it is the prerequisite for deciding how to launch it.
func TestShellShimDetection(t *testing.T) {
	cases := map[string]bool{
		`C:\Program Files\nodejs\npm.cmd`: true,
		`C:\tools\thing.BAT`:              true,
		`C:\tools\thing.bat`:              true,
		`C:\Program Files\nodejs\npm.ps1`: false, // PowerShell script, not a shim
		`/usr/bin/npm`:                    false,
		`/usr/local/bin/python3`:          false,
		`C:\Windows\System32\cmd.exe`:     false,
	}
	for path, want := range cases {
		if got := isShellShim(path); got != want {
			t.Errorf("isShellShim(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestLaunchArgvRoutesWindowsBatchFiles pins the launch decision on every
// platform, since the Windows path cannot be executed here.
//
// The rule being tested: a batch shim is started through cmd.exe on Windows,
// because that is the only way to run one — while every other executable, on
// every platform, is started directly. Arguments stay a slice in both cases;
// Gatekeeper never joins them into a command line itself.
func TestLaunchArgvRoutesWindowsBatchFiles(t *testing.T) {
	cases := []struct {
		name          string
		goos          string
		path          string
		args          []string
		wantArgv      []string
		wantUsedShell bool
	}{
		{
			name:          "a batch shim on Windows goes through cmd.exe",
			goos:          "windows",
			path:          `C:\Program Files\nodejs\npm.cmd`,
			args:          []string{"run", "dev"},
			wantArgv:      []string{"cmd.exe", "/c", `C:\Program Files\nodejs\npm.cmd`, "run", "dev"},
			wantUsedShell: true,
		},
		{
			name:          "a real executable on Windows is started directly",
			goos:          "windows",
			path:          `C:\Windows\System32\where.exe`,
			args:          []string{"node"},
			wantArgv:      []string{`C:\Windows\System32\where.exe`, "node"},
			wantUsedShell: false,
		},
		{
			name:          "a .cmd on Linux is an ordinary file",
			goos:          "linux",
			path:          "/tmp/thing.cmd",
			args:          []string{"a"},
			wantArgv:      []string{"/tmp/thing.cmd", "a"},
			wantUsedShell: false,
		},
		{
			name:          "a normal command on Linux is started directly",
			goos:          "linux",
			path:          "/usr/bin/npm",
			args:          []string{"run", "dev"},
			wantArgv:      []string{"/usr/bin/npm", "run", "dev"},
			wantUsedShell: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argv, usedShell := launchArgv(tc.goos, tc.path, tc.args)
			if usedShell != tc.wantUsedShell {
				t.Errorf("usedShell = %v, want %v", usedShell, tc.wantUsedShell)
			}
			if strings.Join(argv, "\x00") != strings.Join(tc.wantArgv, "\x00") {
				t.Errorf("argv = %q, want %q", argv, tc.wantArgv)
			}
		})
	}
}

// TestLaunchArgvKeepsArgumentsAsSlice is the security property underneath the
// Windows routing: arguments are passed through one by one, never re-joined.
func TestLaunchArgvKeepsArgumentsAsSlice(t *testing.T) {
	tricky := []string{"a b c", "semi;colon", "ampersand&more", `quote"inside`}

	argv, usedShell := launchArgv("windows", `C:\tools\thing.cmd`, tricky)
	if !usedShell {
		t.Fatal("a batch shim was not routed through cmd.exe")
	}

	// The shim's own arguments must still be four separate trailing elements.
	tail := argv[len(argv)-len(tricky):]
	for i := range tricky {
		if tail[i] != tricky[i] {
			t.Errorf("argument %d = %q, want %q", i, tail[i], tricky[i])
		}
	}
}

// TestEnvironmentSliceIsOrdered keeps child environments deterministic, which
// makes test failures and debugging reproducible.
func TestEnvironmentSliceIsOrdered(t *testing.T) {
	got := Environment{"B": "2", "A": "1", "C": "3"}.Slice()
	want := []string{"A=1", "B=2", "C=3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Slice() = %v, want %v", got, want)
	}
}
