package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const version = "0.1.0"

type Severity string

const (
	Pass Severity = "pass"
	Warn Severity = "warn"
	Fail Severity = "fail"
	Info Severity = "info"
)

type Check struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Details     string   `json:"details,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Host      HostInfo  `json:"host"`
	Score     int       `json:"score"`
	Generated time.Time `json:"generated"`
	Checks    []Check   `json:"checks"`
}

type HostInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	Hardware string `json:"hardware"`
}

type MenuItem struct {
	Title       string
	Description string
	Accent      string
	Shortcut    string
	Action      func() Screen
}

type Screen struct {
	Title string
	Body  string
}

func main() {
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "macaudit currently supports macOS only.")
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		handleArgs(os.Args[1:])
		return
	}

	if err := runTUI(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func handleArgs(args []string) {
	switch args[0] {
	case "install":
		if err := installSelf(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "scan":
		report := RunFullScan()
		if contains(args, "--json") {
			out, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(out))
			return
		}
		fmt.Print(renderReport(report))
	case "report":
		if err := handleReport(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "brew":
		fmt.Print(renderChecks(brewChecks()))
	case "browsers":
		fmt.Print(renderChecks(browserChecks()))
	case "startup":
		fmt.Print(renderChecks(startupDeepChecks()))
	case "apps":
		fmt.Print(renderChecks(appChecks()))
	case "secrets":
		target := "."
		if len(args) > 1 {
			target = args[1]
		}
		fmt.Print(renderChecks(secretChecks(target)))
	case "fix":
		fmt.Print(renderChecks(fixChecks(args[1:])))
	case "ir":
		fmt.Print(renderChecks(incidentResponseChecks(args[1:])))
	case "version", "--version", "-v":
		fmt.Println("macaudit", version)
	case "commands", "help", "--help", "-h":
		fmt.Print(helpText())
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", args[0], helpText())
		os.Exit(2)
	}
}

func helpText() string {
	return `macaudit - macOS security audit terminal UI

Usage:
  macaudit              Open the interactive terminal UI
  macaudit install      Install macaudit into ~/.local/bin
  macaudit scan         Run a full audit
  macaudit scan --json  Run a full audit and print JSON
  macaudit report --html Save an HTML audit report
  macaudit report --md   Save a Markdown audit report
  macaudit brew        Audit Homebrew packages and services
  macaudit browsers    Audit browser extension manifests
  macaudit startup     Deep startup and persistence audit
  macaudit apps        Audit /Applications
  macaudit secrets DIR Scan a folder for possible leaked secrets
  macaudit fix --dry-run Show safe fix recommendations
  macaudit ir --last 24h Collect incident-response style signals
  macaudit commands    Show this command reference
  macaudit version      Print version

Navigation:
  Up/Down or j/k        Move
  Enter                 Select
  q or Esc              Quit
`
}

func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not locate current executable: %w", err)
	}
	source, err := filepath.EvalSymlinks(exe)
	if err != nil {
		source = exe
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}
	installDir := filepath.Join(home, ".local", "bin")
	destination := filepath.Join(installDir, "macaudit")

	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("could not create install directory %s: %w", installDir, err)
	}
	if samePath(source, destination) {
		fmt.Printf("macaudit is already installed at %s\n", destination)
		printPathHint(installDir)
		return nil
	}
	if err := copyExecutable(source, destination); err != nil {
		return fmt.Errorf("could not install macaudit to %s: %w", destination, err)
	}
	if err := os.Chmod(destination, 0755); err != nil {
		return fmt.Errorf("installed macaudit but could not mark it executable: %w", err)
	}

	fmt.Printf("Installed macaudit to %s\n", destination)
	printPathHint(installDir)
	return nil
}

func copyExecutable(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := destination + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, destination)
}

func samePath(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	if leftErr == nil && rightErr == nil {
		return os.SameFile(leftInfo, rightInfo)
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func printPathHint(installDir string) {
	if pathContains(installDir) {
		fmt.Println("You can now run: macaudit")
		return
	}
	fmt.Println("Add this to your shell profile if `macaudit` is not found:")
	fmt.Printf("  export PATH=\"$PATH:%s\"\n", installDir)
}

func pathContains(dir string) bool {
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.Clean(entry) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

func RunFullScan() Report {
	checks := []Check{}
	checks = append(checks, coreChecks()...)
	checks = append(checks, privacyChecks()...)
	checks = append(checks, startupDeepChecks()...)
	checks = append(checks, networkChecks()...)
	checks = append(checks, appChecks()...)
	checks = append(checks, developerChecks()...)
	checks = append(checks, brewChecks()...)
	checks = append(checks, browserChecks()...)

	return Report{
		Tool:      "macaudit",
		Version:   version,
		Host:      hostInfo(),
		Generated: time.Now(),
		Score:     score(checks),
		Checks:    checks,
	}
}

func handleReport(args []string) error {
	report := RunFullScan()
	format := "html"
	if contains(args, "--md") || contains(args, "--markdown") {
		format = "md"
	}
	if contains(args, "--html") {
		format = "html"
	}

	output := "macaudit-report.html"
	if format == "md" {
		output = "macaudit-report.md"
	}
	for i, arg := range args {
		if arg == "--out" && i+1 < len(args) {
			output = args[i+1]
		}
	}

	var body string
	if format == "md" {
		body = renderMarkdownReport(report)
	} else {
		body = renderHTMLReport(report)
	}
	if err := os.WriteFile(output, []byte(body), 0644); err != nil {
		return fmt.Errorf("could not write %s report: %w", format, err)
	}
	fmt.Printf("Saved %s report to %s\n", format, output)
	return nil
}

func coreChecks() []Check {
	return []Check{
		fileVaultCheck(),
		firewallCheck(),
		gatekeeperCheck(),
		sipCheck(),
		automaticUpdatesCheck(),
		remoteLoginCheck(),
		guestAccountCheck(),
		appleSiliconCheck(),
	}
}

func fileVaultCheck() Check {
	out, err := command("fdesetup", "status")
	if err != nil {
		return check("filevault", "FileVault disk encryption", "Core", Info, "Unable to read FileVault status.", out, "Run `fdesetup status` locally and confirm full-disk encryption is enabled.")
	}
	if strings.Contains(out, "FileVault is On") {
		return check("filevault", "FileVault disk encryption", "Core", Pass, "FileVault is enabled.", out, "")
	}
	return check("filevault", "FileVault disk encryption", "Core", Fail, "FileVault appears to be disabled.", out, "Enable FileVault in System Settings > Privacy & Security.")
}

func firewallCheck() Check {
	out, err := command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil {
		return check("firewall", "Application firewall", "Core", Info, "Unable to read firewall status.", out, "Open System Settings > Network > Firewall and verify it is enabled.")
	}
	if strings.Contains(strings.ToLower(out), "enabled") {
		return check("firewall", "Application firewall", "Core", Pass, "The application firewall is enabled.", out, "")
	}
	return check("firewall", "Application firewall", "Core", Warn, "The application firewall appears to be disabled.", out, "Enable Firewall in System Settings > Network > Firewall.")
}

func gatekeeperCheck() Check {
	out, err := command("spctl", "--status")
	if err != nil {
		return check("gatekeeper", "Gatekeeper", "Core", Info, "Unable to read Gatekeeper status.", out, "Run `spctl --status` and confirm assessments are enabled.")
	}
	if strings.Contains(out, "assessments enabled") {
		return check("gatekeeper", "Gatekeeper", "Core", Pass, "Gatekeeper assessments are enabled.", out, "")
	}
	return check("gatekeeper", "Gatekeeper", "Core", Fail, "Gatekeeper assessments appear disabled.", out, "Re-enable Gatekeeper with `sudo spctl --master-enable` if appropriate.")
}

func sipCheck() Check {
	out, err := command("csrutil", "status")
	if err != nil {
		return check("sip", "System Integrity Protection", "Core", Info, "Unable to read SIP status.", out, "Boot to recovery if you need to verify SIP manually.")
	}
	if strings.Contains(out, "enabled") {
		return check("sip", "System Integrity Protection", "Core", Pass, "SIP is enabled.", out, "")
	}
	return check("sip", "System Integrity Protection", "Core", Fail, "SIP appears disabled.", out, "Re-enable SIP from macOS Recovery unless you intentionally disabled it for research.")
}

func automaticUpdatesCheck() Check {
	out, err := command("softwareupdate", "--schedule")
	if err != nil {
		return check("auto_updates", "Automatic update schedule", "Core", Info, "Unable to read automatic update schedule.", out, "Verify automatic updates in System Settings > General > Software Update.")
	}
	if strings.Contains(strings.ToLower(out), "on") {
		return check("auto_updates", "Automatic update schedule", "Core", Pass, "Automatic update checks are enabled.", out, "")
	}
	return check("auto_updates", "Automatic update schedule", "Core", Warn, "Automatic update checks may be disabled.", out, "Enable automatic update checks in System Settings.")
}

func remoteLoginCheck() Check {
	out, err := command("systemsetup", "-getremotelogin")
	if err != nil {
		return check("remote_login", "Remote Login / SSH", "Core", Info, "Unable to read Remote Login status.", out, "Check System Settings > General > Sharing > Remote Login.")
	}
	if strings.Contains(strings.ToLower(out), "administrator access") {
		return check("remote_login", "Remote Login / SSH", "Core", Info, "Remote Login status requires administrator access on this Mac.", out, "Check System Settings > General > Sharing > Remote Login.")
	}
	if strings.Contains(out, "Off") {
		return check("remote_login", "Remote Login / SSH", "Core", Pass, "Remote Login is off.", out, "")
	}
	return check("remote_login", "Remote Login / SSH", "Core", Warn, "Remote Login is enabled.", out, "Keep SSH off unless you need it. If enabled, use strong keys and restrict allowed users.")
}

func guestAccountCheck() Check {
	out, err := command("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled")
	if err != nil {
		return check("guest_user", "Guest user", "Core", Info, "Guest user status was not explicitly set or could not be read.", out, "Check System Settings > Users & Groups.")
	}
	if strings.TrimSpace(out) == "0" {
		return check("guest_user", "Guest user", "Core", Pass, "Guest user appears disabled.", out, "")
	}
	return check("guest_user", "Guest user", "Core", Warn, "Guest user may be enabled.", out, "Disable Guest User unless you intentionally allow temporary local access.")
}

func appleSiliconCheck() Check {
	if runtime.GOARCH == "arm64" {
		return check("hardware_arch", "Hardware architecture", "Core", Info, "Running on Apple Silicon.", "arch=arm64", "For stronger boot protections, review Startup Security Utility policies.")
	}
	return check("hardware_arch", "Hardware architecture", "Core", Info, "Running on Intel Mac.", "arch=amd64", "Some Apple Silicon checks do not apply to Intel Macs.")
}

func privacyChecks() []Check {
	checks := []Check{
		check("full_disk_access", "Full Disk Access permission", "Privacy", Info, "Some macOS audit checks need Full Disk Access for complete results.", "", fullDiskAccessInstructions()),
	}
	db := filepath.Join(os.Getenv("HOME"), "Library/Application Support/com.apple.TCC/TCC.db")
	if _, err := os.Stat(db); err != nil {
		checks = append(checks, check("privacy_tcc", "Privacy permissions database", "Privacy", Info, "User TCC database is not readable from this terminal session.", db, fullDiskAccessInstructions()))
		return checks
	}
	checks = append(checks, check("privacy_tcc", "Privacy permissions database", "Privacy", Info, "User privacy permission database exists.", db, "Future versions can parse camera, microphone, accessibility, and screen recording grants."))
	return checks
}

func startupChecks() []Check {
	paths := []string{
		filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents"),
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
	}
	count := 0
	var samples []string
	for _, p := range paths {
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			count++
			if len(samples) < 8 {
				samples = append(samples, filepath.Join(p, entry.Name()))
			}
		}
	}
	sev := Info
	summary := fmt.Sprintf("Found %d LaunchAgent/LaunchDaemon plist files.", count)
	if count > 60 {
		sev = Warn
		summary = fmt.Sprintf("Found %d startup plist files, which is worth reviewing.", count)
	}
	return []Check{check("startup_plists", "LaunchAgents and LaunchDaemons", "Startup", sev, summary, strings.Join(samples, "\n"), "Review unknown or unsigned startup items.")}
}

func startupDeepChecks() []Check {
	checks := startupChecks()
	checks = append(checks, shellStartupChecks()...)
	checks = append(checks, cronChecks()...)
	return checks
}

func shellStartupChecks() []Check {
	home := os.Getenv("HOME")
	files := []string{".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"}
	found := []string{}
	suspicious := []string{}
	for _, name := range files {
		path := filepath.Join(home, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = append(found, path)
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") || strings.Contains(lower, "nc ") || strings.Contains(lower, "base64") {
			suspicious = append(suspicious, path)
		}
	}
	if len(found) == 0 {
		return []Check{check("shell_startup_files", "Shell startup files", "Startup", Info, "No common shell startup files were found.", "", "")}
	}
	if len(suspicious) > 0 {
		return []Check{check("shell_startup_files", "Shell startup files", "Startup", Warn, "Some shell startup files contain commands worth reviewing.", strings.Join(suspicious, "\n"), "Open these files and verify every network/download command is expected.")}
	}
	return []Check{check("shell_startup_files", "Shell startup files", "Startup", Info, fmt.Sprintf("Found %d shell startup file(s).", len(found)), strings.Join(found, "\n"), "Review shell startup files when investigating persistence.")}
}

func cronChecks() []Check {
	out, err := commandWithTimeout(3*time.Second, "crontab", "-l")
	if err != nil {
		return []Check{check("user_crontab", "User crontab", "Startup", Info, "No user crontab was found or crontab could not be read.", strings.TrimSpace(out), "This is normal on many Macs.")}
	}
	return []Check{check("user_crontab", "User crontab", "Startup", Warn, "A user crontab exists.", firstLines(out, 20), "Review scheduled commands and remove anything unknown with `crontab -e`.")}
}

func networkChecks() []Check {
	checks := []Check{}
	listen, err := command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil {
		checks = append(checks, check("listening_ports", "Listening TCP ports", "Network", Info, "Unable to inspect listening ports.", listen, "Run `lsof -nP -iTCP -sTCP:LISTEN` manually."))
	} else {
		lines := nonEmptyLines(listen)
		sev := Info
		summary := "No listening TCP services found."
		if len(lines) > 1 {
			sev = Warn
			summary = fmt.Sprintf("Found %d listening TCP service rows.", len(lines)-1)
		}
		checks = append(checks, check("listening_ports", "Listening TCP ports", "Network", sev, summary, firstLines(listen, 12), "Review exposed local services and disable anything you do not use."))
	}

	dns := dnsServers()
	checks = append(checks, check("dns_servers", "DNS servers", "Network", Info, fmt.Sprintf("Detected %d DNS server(s).", len(dns)), strings.Join(dns, "\n"), "Use trusted DNS resolvers and review unexpected network profiles."))
	return checks
}

func appChecks() []Check {
	checks := []Check{}
	apps, err := filepath.Glob("/Applications/*.app")
	if err != nil || len(apps) == 0 {
		return []Check{check("applications_folder", "Applications folder", "Apps", Info, "No apps were found in /Applications or the folder could not be read.", "/Applications", fullDiskAccessInstructions())}
	}
	sort.Strings(apps)
	checks = append(checks, check("applications_folder", "Applications folder", "Apps", Info, fmt.Sprintf("Found %d app bundle(s) in /Applications.", len(apps)), firstLines(strings.Join(apps, "\n"), 12), "Review apps you do not recognize."))

	quarantined := []string{}
	for _, app := range apps {
		if len(quarantined) >= 8 {
			break
		}
		if out, err := commandWithTimeout(2*time.Second, "xattr", "-p", "com.apple.quarantine", app); err == nil && strings.TrimSpace(out) != "" {
			quarantined = append(quarantined, app)
		}
	}
	if len(quarantined) == 0 {
		checks = append(checks, check("quarantined_apps", "Downloaded app quarantine flags", "Apps", Pass, "No quarantine flags found in the sampled /Applications apps.", "", ""))
	} else {
		checks = append(checks, check("quarantined_apps", "Downloaded app quarantine flags", "Apps", Info, fmt.Sprintf("Found %d app(s) with download quarantine metadata.", len(quarantined)), strings.Join(quarantined, "\n"), "This can be normal for downloaded apps. Investigate anything unfamiliar."))
	}

	unsigned := []string{}
	scanned := 0
	for _, app := range apps {
		if scanned >= 25 || len(unsigned) >= 8 {
			break
		}
		scanned++
		if _, err := commandWithTimeout(2*time.Second, "codesign", "--verify", app); err != nil {
			unsigned = append(unsigned, app)
		}
	}
	if len(unsigned) == 0 {
		checks = append(checks, check("unsigned_apps", "Unsigned applications", "Apps", Pass, fmt.Sprintf("No unsigned apps found in the first %d app(s) checked.", scanned), "", ""))
		return checks
	}
	checks = append(checks, check("unsigned_apps", "Unsigned applications", "Apps", Warn, fmt.Sprintf("Found %d app(s) that failed code-signature verification in a fast sample.", len(unsigned)), strings.Join(unsigned, "\n"), "Investigate apps you do not recognize. Some developer tools may fail signing checks legitimately."))
	return checks
}

func developerChecks() []Check {
	checks := []Check{}
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	privateKeys, _ := filepath.Glob(filepath.Join(sshDir, "id_*"))
	weak := []string{}
	for _, key := range privateKeys {
		if strings.HasSuffix(key, ".pub") {
			continue
		}
		info, err := os.Stat(key)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0077 != 0 {
			weak = append(weak, fmt.Sprintf("%s (%s)", key, info.Mode().Perm()))
		}
	}
	if len(weak) == 0 {
		checks = append(checks, check("ssh_key_permissions", "SSH private key permissions", "Developer", Pass, "No weak SSH private key permissions found.", "", ""))
	} else {
		checks = append(checks, check("ssh_key_permissions", "SSH private key permissions", "Developer", Fail, "Some SSH private keys are readable by group or others.", strings.Join(weak, "\n"), "Run `chmod 600 ~/.ssh/<private-key>` for affected keys."))
	}
	return checks
}

func brewChecks() []Check {
	if _, err := exec.LookPath("brew"); err != nil {
		return []Check{check("homebrew_installed", "Homebrew", "Homebrew", Info, "Homebrew is not installed or not in PATH.", "", "Skip this if you do not use Homebrew. Otherwise install Homebrew from https://brew.sh.")}
	}
	checks := []Check{}
	version, _ := commandWithTimeout(3*time.Second, "brew", "--version")
	checks = append(checks, check("homebrew_installed", "Homebrew", "Homebrew", Pass, "Homebrew is installed.", firstLines(version, 3), ""))

	outdated, err := commandWithTimeout(8*time.Second, "brew", "outdated", "--quiet")
	if err != nil && strings.TrimSpace(outdated) == "" {
		checks = append(checks, check("homebrew_outdated", "Outdated Homebrew packages", "Homebrew", Info, "Could not check outdated packages.", outdated, "Run `brew outdated` manually."))
	} else if len(brewDataLines(outdated)) == 0 {
		checks = append(checks, check("homebrew_outdated", "Outdated Homebrew packages", "Homebrew", Pass, "No outdated Homebrew packages were reported.", "", ""))
	} else {
		lines := brewDataLines(outdated)
		checks = append(checks, check("homebrew_outdated", "Outdated Homebrew packages", "Homebrew", Warn, fmt.Sprintf("%d Homebrew package(s) are outdated.", len(lines)), firstLines(outdated, 20), "Run `brew update` and `brew upgrade` after reviewing changes."))
	}

	services, err := commandWithTimeout(5*time.Second, "brew", "services", "list")
	if err != nil && strings.TrimSpace(services) == "" {
		checks = append(checks, check("brew_services", "Homebrew services", "Homebrew", Info, "Could not read Homebrew services.", services, "Run `brew services list` manually."))
	} else {
		running := []string{}
		for _, line := range nonEmptyLines(services) {
			if strings.Contains(line, "started") {
				running = append(running, line)
			}
		}
		if len(running) > 0 {
			checks = append(checks, check("brew_services", "Homebrew services", "Homebrew", Warn, fmt.Sprintf("%d Homebrew service(s) are running.", len(running)), strings.Join(running, "\n"), "Stop services you do not need with `brew services stop <name>`."))
		} else {
			checks = append(checks, check("brew_services", "Homebrew services", "Homebrew", Pass, "No running Homebrew services were found.", firstLines(services, 8), ""))
		}
	}
	return checks
}

func brewDataLines(out string) []string {
	lines := []string{}
	for _, line := range nonEmptyLines(out) {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "warning:") || strings.HasPrefix(lower, "error:") || strings.HasPrefix(trimmed, "✘") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func browserChecks() []Check {
	checks := []Check{}
	extensionRoots := []string{
		filepath.Join(os.Getenv("HOME"), "Library/Application Support/Google/Chrome/Default/Extensions"),
		filepath.Join(os.Getenv("HOME"), "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
		filepath.Join(os.Getenv("HOME"), "Library/Application Support/Microsoft Edge/Default/Extensions"),
	}
	found := []string{}
	risky := []string{}
	for _, root := range extensionRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ext := range entries {
			if !ext.IsDir() {
				continue
			}
			versions, err := os.ReadDir(filepath.Join(root, ext.Name()))
			if err != nil {
				continue
			}
			for _, versionDir := range versions {
				manifestPath := filepath.Join(root, ext.Name(), versionDir.Name(), "manifest.json")
				name, permissions := readExtensionManifest(manifestPath)
				if name == "" {
					continue
				}
				line := fmt.Sprintf("%s (%s)", name, ext.Name())
				found = append(found, line)
				if riskyPermissions(permissions) {
					risky = append(risky, fmt.Sprintf("%s permissions=%s", line, strings.Join(permissions, ",")))
				}
				break
			}
		}
	}

	firefox := filepath.Join(os.Getenv("HOME"), "Library/Application Support/Firefox/Profiles")
	if profiles, err := os.ReadDir(firefox); err == nil {
		for _, profile := range profiles {
			data, err := os.ReadFile(filepath.Join(firefox, profile.Name(), "extensions.json"))
			if err == nil && len(data) > 0 {
				found = append(found, "Firefox profile: "+profile.Name())
			}
		}
	}

	if len(found) == 0 {
		return []Check{check("browser_extensions", "Browser extensions", "Browsers", Info, "No browser extension manifests were found in common profile paths.", "", "This can be normal if you use a different browser profile.")}
	}
	checks = append(checks, check("browser_extensions", "Browser extensions", "Browsers", Info, fmt.Sprintf("Found %d browser extension/profile item(s).", len(found)), firstLines(strings.Join(found, "\n"), 25), "Review extensions you do not recognize."))
	if len(risky) > 0 {
		checks = append(checks, check("browser_extension_permissions", "Risky browser extension permissions", "Browsers", Warn, fmt.Sprintf("%d extension(s) request broad permissions.", len(risky)), firstLines(strings.Join(risky, "\n"), 20), "Remove unknown extensions or limit their site access in browser settings."))
	} else {
		checks = append(checks, check("browser_extension_permissions", "Risky browser extension permissions", "Browsers", Pass, "No broad-risk extension permissions were found in parsed manifests.", "", ""))
	}
	return checks
}

func readExtensionManifest(path string) (string, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", nil
	}
	name, _ := manifest["name"].(string)
	permissions := []string{}
	for _, key := range []string{"permissions", "host_permissions"} {
		if values, ok := manifest[key].([]any); ok {
			for _, value := range values {
				if text, ok := value.(string); ok {
					permissions = append(permissions, text)
				}
			}
		}
	}
	return name, permissions
}

func riskyPermissions(permissions []string) bool {
	for _, permission := range permissions {
		p := strings.ToLower(permission)
		if p == "<all_urls>" || strings.Contains(p, "://*/*") || p == "tabs" || p == "webrequest" || p == "cookies" || p == "nativeMessaging" {
			return true
		}
	}
	return false
}

func secretChecks(target string) []Check {
	root, err := filepath.Abs(target)
	if err != nil {
		root = target
	}
	info, err := os.Stat(root)
	if err != nil {
		return []Check{check("secrets_scan", "Secrets scan", "Secrets", Info, "Could not open scan target.", root, "Pass a folder path, for example `macaudit secrets ~/Code`.")}
	}
	if !info.IsDir() {
		return []Check{check("secrets_scan", "Secrets scan", "Secrets", Info, "Secrets scan target is not a folder.", root, "Pass a folder path, for example `macaudit secrets ~/Code`.")}
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_\-./+]{16,}`),
		regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	}
	findings := []string{}
	scanned := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || len(findings) >= 30 {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldScanFile(name) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		scanned++
		text := string(data)
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				findings = append(findings, path)
				break
			}
		}
		return nil
	})

	if len(findings) == 0 {
		return []Check{check("secrets_scan", "Secrets scan", "Secrets", Pass, fmt.Sprintf("Scanned %d text/config file(s); no obvious secrets found.", scanned), root, "")}
	}
	return []Check{check("secrets_scan", "Secrets scan", "Secrets", Fail, fmt.Sprintf("Found %d file(s) that may contain secrets.", len(findings)), strings.Join(findings, "\n"), "Remove real secrets, rotate exposed tokens, and add safe examples like `.env.example`.")}
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", ".gocache", ".next", "Pods", ".venv", "venv":
		return true
	}
	return false
}

func shouldScanFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".env") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") {
		return true
	}
	ext := filepath.Ext(lower)
	switch ext {
	case ".env", ".txt", ".json", ".yml", ".yaml", ".toml", ".ini", ".conf", ".pem", ".key", ".sh", ".zsh", ".bash", ".js", ".ts", ".py", ".go", ".rb", ".php":
		return true
	}
	return false
}

func fixChecks(args []string) []Check {
	dryRun := contains(args, "--dry-run")
	safe := contains(args, "--safe") || dryRun || len(args) == 0
	if !safe {
		return []Check{check("fix_mode", "Safe fix mode", "Fix", Info, "Only safe fix recommendations are supported right now.", "", "Use `macaudit fix --dry-run` or `macaudit fix --safe`.")}
	}
	mode := "Safe fix plan"
	if dryRun {
		mode = "Dry-run fix plan"
	}
	return []Check{
		check("fix_firewall", mode+": firewall", "Fix", Info, "If the firewall is off, enable it manually or with an admin command.", "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "macaudit does not run privileged changes automatically yet."),
		check("fix_updates", mode+": automatic updates", "Fix", Info, "Keep automatic update checks enabled.", "sudo softwareupdate --schedule on", "Review macOS update settings in System Settings > General > Software Update."),
		check("fix_filevault", mode+": FileVault", "Fix", Info, "FileVault protects data at rest if your Mac is lost.", "System Settings > Privacy & Security > FileVault", "Enable FileVault manually and store the recovery key safely."),
		check("fix_full_disk_access", mode+": Full Disk Access", "Fix", Info, "Full Disk Access lets macaudit inspect more privacy and persistence locations.", "", fullDiskAccessInstructions()),
	}
}

func incidentResponseChecks(args []string) []Check {
	window := "24h"
	for i, arg := range args {
		if arg == "--last" && i+1 < len(args) {
			window = args[i+1]
		}
	}
	checks := []Check{
		check("ir_window", "Collection window", "Incident Response", Info, "Incident response collection is local and read-only.", "last="+window, "Use this output as a quick triage bundle, not a forensic guarantee."),
	}
	if out, err := commandWithTimeout(4*time.Second, "who"); err == nil {
		checks = append(checks, check("ir_logged_in_users", "Logged-in users", "Incident Response", Info, "Current logged-in sessions collected.", out, "Investigate unknown sessions."))
	}
	if out, err := commandWithTimeout(4*time.Second, "last", "-10"); err == nil {
		checks = append(checks, check("ir_recent_logins", "Recent logins", "Incident Response", Info, "Recent login history collected.", out, "Investigate unknown logins or strange times."))
	}
	if out, err := commandWithTimeout(5*time.Second, "ps", "axo", "pid,ppid,user,comm"); err == nil {
		checks = append(checks, check("ir_processes", "Running processes", "Incident Response", Info, "Running process list collected.", firstLines(out, 30), "Investigate unknown processes."))
	}
	if out, err := commandWithTimeout(5*time.Second, "lsof", "-nP", "-i"); err == nil {
		checks = append(checks, check("ir_network", "Network activity", "Incident Response", Info, "Network activity collected.", firstLines(out, 30), "Look for unfamiliar remote hosts or listening services."))
	}
	checks = append(checks, recentDownloadsCheck())
	return checks
}

func recentDownloadsCheck() Check {
	dir := filepath.Join(os.Getenv("HOME"), "Downloads")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return check("ir_recent_downloads", "Recent downloads", "Incident Response", Info, "Downloads folder could not be read.", dir, fullDiskAccessInstructions())
	}
	type fileMod struct {
		path string
		mod  time.Time
	}
	files := []fileMod{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && !info.IsDir() {
			files = append(files, fileMod{filepath.Join(dir, entry.Name()), info.ModTime()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	lines := []string{}
	for i, file := range files {
		if i >= 12 {
			break
		}
		lines = append(lines, fmt.Sprintf("%s  %s", file.mod.Format("2006-01-02 15:04"), file.path))
	}
	return check("ir_recent_downloads", "Recent downloads", "Incident Response", Info, fmt.Sprintf("Collected %d recent download item(s).", len(lines)), strings.Join(lines, "\n"), "Investigate recently downloaded apps, archives, scripts, and installers.")
}

func hostInfo() HostInfo {
	kernel, _ := command("uname", "-r")
	hardware, _ := command("uname", "-m")
	return HostInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   strings.TrimSpace(kernel),
		Hardware: strings.TrimSpace(hardware),
	}
}

func score(checks []Check) int {
	points := 100
	for _, c := range checks {
		switch c.Severity {
		case Fail:
			points -= 14
		case Warn:
			points -= 7
		}
	}
	if points < 0 {
		return 0
	}
	return points
}

func command(name string, args ...string) (string, error) {
	return commandWithTimeout(6*time.Second, name, args...)
}

func commandWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if filepath.Base(name) == "brew" {
		cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1")
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.String(), ctx.Err()
	}
	return strings.TrimSpace(out.String()), err
}

func dnsServers() []string {
	servers := []string{}
	conf, err := os.Open("/etc/resolv.conf")
	if err == nil {
		defer conf.Close()
		scanner := bufio.NewScanner(conf)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
				servers = append(servers, fields[1])
			}
		}
	}
	sort.Strings(servers)
	return unique(servers)
}

func check(id, title, category string, sev Severity, summary, details, remediation string) Check {
	return Check{ID: id, Title: title, Category: category, Severity: sev, Summary: summary, Details: details, Remediation: remediation}
}

func runTUI() error {
	oldState, err := enterRawMode()
	if err != nil {
		return err
	}
	defer restoreTerminal(oldState)

	items := []MenuItem{
		{"Run full scan", "Audit core macOS security, startup items, network exposure, apps, and developer settings.", "\033[38;5;117m", "01", func() Screen { return Screen{"Full Scan", renderReport(RunFullScan())} }},
		{"Core security", "FileVault, firewall, Gatekeeper, SIP, updates, SSH, guest user, and CPU architecture.", "\033[38;5;120m", "02", func() Screen { return Screen{"Core Security", renderChecks(coreChecks())} }},
		{"Privacy permissions", "Inspect what macaudit can see about macOS privacy permission databases.", "\033[38;5;213m", "03", func() Screen { return Screen{"Privacy Permissions", renderChecks(privacyChecks())} }},
		{"Startup & persistence", "Review LaunchAgents, LaunchDaemons, shell startup files, and crontab.", "\033[38;5;222m", "04", func() Screen { return Screen{"Startup & Persistence", renderChecks(startupDeepChecks())} }},
		{"Network exposure", "Show listening ports and DNS servers to help spot unexpected services.", "\033[38;5;81m", "05", func() Screen { return Screen{"Network Exposure", renderChecks(networkChecks())} }},
		{"Applications", "Fast /Applications review: app count, quarantine flags, and signature sample.", "\033[38;5;177m", "06", func() Screen { return Screen{"Applications", renderChecks(appChecks())} }},
		{"Developer checks", "SSH key permission checks, with room for secrets scanning later.", "\033[38;5;156m", "07", func() Screen { return Screen{"Developer Checks", renderChecks(developerChecks())} }},
		{"Homebrew audit", "Check Homebrew version, outdated packages, and running brew services.", "\033[38;5;141m", "08", func() Screen { return Screen{"Homebrew Audit", renderChecks(brewChecks())} }},
		{"Browser extensions", "Parse common Chrome, Brave, Edge, and Firefox extension data.", "\033[38;5;45m", "09", func() Screen { return Screen{"Browser Extensions", renderChecks(browserChecks())} }},
		{"Secrets scan", "Scan the current folder for possible API keys, tokens, and private keys.", "\033[38;5;203m", "10", func() Screen { return Screen{"Secrets Scan", renderChecks(secretChecks("."))} }},
		{"Safe fix plan", "Show safe fix recommendations without changing privileged settings.", "\033[38;5;220m", "11", func() Screen { return Screen{"Safe Fix Plan", renderChecks(fixChecks([]string{"--dry-run"}))} }},
		{"Incident response", "Collect quick local triage signals like logins, processes, network, and downloads.", "\033[38;5;111m", "12", func() Screen {
			return Screen{"Incident Response", renderChecks(incidentResponseChecks([]string{"--last", "24h"}))}
		}},
		{"Command help", "Show every typable macaudit command and what it does.", "\033[38;5;215m", "13", func() Screen { return Screen{"Command Help", helpText()} }},
		{"About", "Author, install, usage, and GitHub download notes.", "\033[38;5;215m", "14", func() Screen { return Screen{"About", aboutText()} }},
		{"Quit", "Leave macaudit.", "\033[38;5;244m", "15", func() Screen { return Screen{Title: "quit"} }},
	}

	selected := 0
	for {
		drawMenu(items, selected)
		key, err := readKey(os.Stdin)
		if err != nil {
			return err
		}
		switch key {
		case "up":
			if selected > 0 {
				selected--
			}
		case "down":
			if selected < len(items)-1 {
				selected++
			}
		case "enter":
			drawLoading(items[selected])
			screen := items[selected].Action()
			if screen.Title == "quit" {
				clearScreen()
				return nil
			}
			drawScreen(screen)
			_, _ = readKey(os.Stdin)
		case "q", "esc":
			clearScreen()
			return nil
		}
	}
}

func drawLoading(item MenuItem) {
	clearScreen()
	fmt.Printf("  \033[1;38;5;230m%s\033[0m\n", item.Title)
	fmt.Print("  \033[38;5;209m------------------------------------------------------------\033[0m\n\n")
	fmt.Printf("  \033[38;5;250mRunning %s...\033[0m\n", strings.ToLower(item.Title))
	fmt.Print("  \033[38;5;238mThis may take a few seconds on larger Macs.\033[0m\n")
}

func drawMenu(items []MenuItem, selected int) {
	clearScreen()
	fmt.Print("\033[1;38;5;230m  macaudit\033[0m\n\n")
	fmt.Print("\033[38;5;209m")
fmt.Print("    █▀▄▀█ █▀█ █▀▀ █▀█ █░█ █▀▄ █ ▀█▀ \n")
fmt.Print("    █░▀░█ █▀█ █▄▄ █▀█ █▄█ █▄▀ █ ░█░ \n")
	fmt.Print("\033[0m\n")
	fmt.Printf("  \033[38;5;209mMacaudit CLI v%s\033[0m\n", version)
	fmt.Print("  \033[38;5;250mCreated by Bhavya Sharma (@bhavyavashisth)\033[0m\n\n")
	fmt.Print("  \033[38;5;226m?\033[0m \033[1;38;5;230mWhat would you like to audit?\033[0m \033[38;5;250m(Use arrow keys)\033[0m\n")
	for i, item := range items {
		if i == selected {
			fmt.Printf("  \033[38;5;45m>\033[0m \033[48;5;236m%s %-28s\033[0m \033[38;5;244m%s\033[0m\n", item.Accent, item.Title, item.Shortcut)
			continue
		}
		if item.Title == "Homebrew audit" {
			fmt.Print("  \033[38;5;244m--- Extended Audits ---\033[0m\n")
		}
		if item.Title == "Command help" {
			fmt.Print("  \033[38;5;244m--- Project ---\033[0m\n")
		}
		if item.Title == "Quit" {
			fmt.Print("  \033[38;5;244m--- Help ---\033[0m\n")
		}
		fmt.Printf("    %s%-30s\033[0m \033[38;5;244m%s\033[0m\n", item.Accent, item.Title, item.Shortcut)
		if i == selected {
			fmt.Printf("    \033[38;5;245m%s\033[0m\n", item.Description)
			continue
		}
	}
	fmt.Printf("\n  \033[38;5;250m%s\033[0m\n", items[selected].Description)
	fmt.Print("  \033[38;5;238mTip: run `macaudit scan --json` for automation-friendly output.\033[0m\n")
}

func drawScreen(screen Screen) {
	clearScreen()
	fmt.Printf("  \033[1;38;5;230m%s\033[0m\n", screen.Title)
	fmt.Print("  \033[38;5;209m------------------------------------------------------------\033[0m\n\n")
	fmt.Print(screen.Body)
	fmt.Print("\n\033[38;5;250mPress any key to return.\033[0m")
}

func renderReport(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\033[1mScore\033[0m %s  \033[38;5;250m%s/%s · generated %s\033[0m\n\n", scoreBadge(report.Score), report.Host.OS, report.Host.Arch, report.Generated.Format(time.RFC3339))
	b.WriteString(renderChecks(report.Checks))
	return b.String()
}

func renderChecks(checks []Check) string {
	var b strings.Builder
	for _, c := range checks {
		fmt.Fprintf(&b, "%s %s\n", badge(c.Severity), c.Title)
		fmt.Fprintf(&b, "  Category: %s\n", c.Category)
		fmt.Fprintf(&b, "  %s: %s\n", issueLabel(c.Severity), c.Summary)
		if c.Details != "" {
			fmt.Fprintf(&b, "  Details:\n%s\n", indent(c.Details, "    "))
		}
		if c.Remediation != "" {
			fmt.Fprintf(&b, "  What to do: %s\n", c.Remediation)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func issueLabel(sev Severity) string {
	switch sev {
	case Pass:
		return "Status"
	case Warn, Fail:
		return "Issue"
	default:
		return "Note"
	}
}

func badge(sev Severity) string {
	switch sev {
	case Pass:
		return "\033[38;5;120mPASS\033[0m"
	case Warn:
		return "\033[38;5;222mWARN\033[0m"
	case Fail:
		return "\033[38;5;203mFAIL\033[0m"
	default:
		return "\033[38;5;117mINFO\033[0m"
	}
}

func scoreBadge(score int) string {
	color := "\033[38;5;120m"
	if score < 80 {
		color = "\033[38;5;222m"
	}
	if score < 60 {
		color = "\033[38;5;203m"
	}
	return fmt.Sprintf("%s%d/100\033[0m", color, score)
}

func renderMarkdownReport(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# macaudit report\n\n")
	fmt.Fprintf(&b, "- Score: %d/100\n", report.Score)
	fmt.Fprintf(&b, "- Host: %s/%s\n", report.Host.OS, report.Host.Arch)
	fmt.Fprintf(&b, "- Generated: %s\n\n", report.Generated.Format(time.RFC3339))
	for _, c := range report.Checks {
		fmt.Fprintf(&b, "## %s - %s\n\n", strings.ToUpper(string(c.Severity)), c.Title)
		fmt.Fprintf(&b, "- Category: %s\n", c.Category)
		fmt.Fprintf(&b, "- %s: %s\n", issueLabel(c.Severity), c.Summary)
		if c.Details != "" {
			fmt.Fprintf(&b, "\n```text\n%s\n```\n", c.Details)
		}
		if c.Remediation != "" {
			fmt.Fprintf(&b, "\nWhat to do: %s\n", c.Remediation)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func renderHTMLReport(report Report) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>macaudit report</title>")
	b.WriteString("<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:32px;background:#101414;color:#f4efe7}main{max-width:980px;margin:auto}.card{border:1px solid #333;padding:16px;margin:12px 0;background:#171b1b;border-radius:8px}.pass{color:#8ee88e}.warn{color:#ffd166}.fail{color:#ff6b6b}.info{color:#7bdff2}pre{white-space:pre-wrap;background:#0b0e0e;padding:12px;border-radius:6px;color:#d5d5d5}.meta{color:#aaa}</style></head><body><main>")
	fmt.Fprintf(&b, "<h1>macaudit report</h1><p class=\"meta\">Score %d/100 · %s/%s · %s</p>", report.Score, html.EscapeString(report.Host.OS), html.EscapeString(report.Host.Arch), html.EscapeString(report.Generated.Format(time.RFC3339)))
	for _, c := range report.Checks {
		sev := html.EscapeString(string(c.Severity))
		fmt.Fprintf(&b, "<section class=\"card\"><h2><span class=\"%s\">%s</span> %s</h2>", sev, strings.ToUpper(sev), html.EscapeString(c.Title))
		fmt.Fprintf(&b, "<p class=\"meta\">Category: %s</p>", html.EscapeString(c.Category))
		fmt.Fprintf(&b, "<p><strong>%s:</strong> %s</p>", html.EscapeString(issueLabel(c.Severity)), html.EscapeString(c.Summary))
		if c.Details != "" {
			fmt.Fprintf(&b, "<pre>%s</pre>", html.EscapeString(c.Details))
		}
		if c.Remediation != "" {
			fmt.Fprintf(&b, "<p><strong>What to do:</strong> %s</p>", html.EscapeString(c.Remediation))
		}
		b.WriteString("</section>")
	}
	b.WriteString("</main></body></html>")
	return b.String()
}

func aboutText() string {
	return `macaudit is a local-first macOS security audit CLI.

Author:

  Bhavya Sharma
  GitHub: https://github.com/bhavyavashisth

Open the terminal UI:

  macaudit

Useful commands:

  macaudit install
  macaudit scan
  macaudit scan --json
  macaudit report --html
  macaudit report --md
  macaudit brew
  macaudit browsers
  macaudit startup
  macaudit apps
  macaudit secrets ~/Code
  macaudit fix --dry-run
  macaudit ir --last 24h
  macaudit commands
  macaudit version

Download from GitHub:

  git clone https://github.com/bhavyavashisth/macaudit.git
  cd macaudit
  make build-all
  ./dist/macaudit-darwin-universal install
  macaudit

macOS permissions:

  To give deeper audit permission:
  1. Open System Settings
  2. Go to Privacy & Security
  3. Open Full Disk Access
  4. Add your terminal app, like Terminal, iTerm, or Codex
  5. Turn it on, then restart that terminal

Install the current binary:

  ./dist/macaudit-darwin-universal install

Release builds:

  make build-all

Roadmap:

  - deeper TCC privacy parsing
  - signed release packages
  - optional privileged helper for safe fixes
  - richer app notarization checks
`
}

func fullDiskAccessInstructions() string {
	return "Open System Settings > Privacy & Security > Full Disk Access. Add Terminal, iTerm, or Codex, enable it, then restart that terminal."
}

func enterRawMode() (string, error) {
	oldState, err := terminalState()
	if err != nil {
		return "", fmt.Errorf("failed to read terminal state: %w", err)
	}
	cmd := exec.Command("stty", "-echo", "cbreak")
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to enter raw mode: %w", err)
	}
	fmt.Print("\033[?25l")
	return oldState, nil
}

func terminalState() (string, error) {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func restoreTerminal(oldState string) {
	if oldState != "" {
		cmd := exec.Command("stty", strings.Fields(oldState)...)
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
	}
	fmt.Print("\033[?25h\033[0m")
}

func readKey(r io.Reader) (string, error) {
	buf := make([]byte, 3)
	n, err := r.Read(buf)
	if err != nil {
		return "", err
	}
	if n == 1 {
		switch buf[0] {
		case 3, 27:
			return "esc", nil
		case 13, 10:
			return "enter", nil
		case 'q':
			return "q", nil
		case 'k':
			return "up", nil
		case 'j':
			return "down", nil
		}
	}
	if n >= 3 && buf[0] == 27 && buf[1] == '[' {
		switch buf[2] {
		case 'A':
			return "up", nil
		case 'B':
			return "down", nil
		}
	}
	return "", nil
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func nonEmptyLines(s string) []string {
	lines := []string{}
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func firstLines(s string, max int) string {
	lines := nonEmptyLines(s)
	if len(lines) <= max {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:max], "\n") + "\n..."
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func unique(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
