package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const defaultAuthConfig = "/etc/soar-client/client.json"

// runAuth is the small, user-facing way to change the SOCKS credentials. It
// updates the JSON file atomically and validates the result before replacing
// the original. Interactive mode hides the password.
func runAuth(args []string) error {
	fs := flag.NewFlagSet("soar-client auth", flag.ContinueOnError)
	configPath := fs.String("config", defaultAuthConfig, "client JSON configuration to update")
	username := fs.String("username", "", "new SOCKS username (prompt if omitted)")
	password := fs.String("password", "", "new SOCKS password (prompt if omitted)")
	listen := fs.String("listen", "", "new SOCKS listen address (optional)")
	restart := fs.Bool("restart", false, "restart soar-client.service after updating")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if filepath.Clean(*configPath) == defaultAuthConfig && os.Geteuid() != 0 {
		return errors.New("run this command with sudo (the default config is owned by root)")
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	user := *username
	if !set["username"] {
		v, err := promptLine("SOCKS username: ")
		if err != nil {
			return err
		}
		user = v
	}
	pass := *password
	if !set["password"] {
		fmt.Fprint(os.Stderr, "SOCKS password (hidden): ")
		v, err := readPasswordLine(os.Stdin)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pass = v
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return errors.New("username must not be empty")
	}
	if pass == "" {
		return errors.New("password must not be empty")
	}
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("username and password must each be at most 255 bytes")
	}

	listenValue := ""
	if set["listen"] {
		listenValue = strings.TrimSpace(*listen)
		if listenValue == "" {
			return errors.New("-listen must not be empty")
		}
	}

	if err := updateAuthConfig(*configPath, user, pass, listenValue); err != nil {
		return err
	}

	fmt.Printf("Updated %s\n", *configPath)
	fmt.Printf("  username: %s\n", user)
	if listenValue != "" {
		fmt.Printf("  listen:   %s\n", listenValue)
	}
	warnOverrides(*configPath, listenValue != "")

	if *restart {
		if err := restartSoarClient(); err != nil {
			return err
		}
		fmt.Println("Restarted soar-client.service.")
	} else {
		fmt.Println("Restart it with: systemctl restart soar-client")
	}
	return nil
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := readLine(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func readLine(f *os.File) (string, error) {
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// updateAuthConfig preserves every existing JSON field and only replaces the
// credential/listener keys. The temp file is validated before the rename, so a
// bad listener/credential combination cannot replace a working config.
func updateAuthConfig(path, username, password, listen string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s is not a valid JSON object: %w", path, err)
	}
	if doc == nil {
		doc = map[string]json.RawMessage{}
	}
	doc["username"], _ = json.Marshal(username)
	doc["password"], _ = json.Marshal(password)
	if listen != "" {
		doc["listen"], _ = json.Marshal(listen)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create a temporary file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := loadConfigValidated(tmpName); err != nil {
		return fmt.Errorf("refusing to write invalid config: %w", err)
	}
	if err := preserveOwner(tmpName, info); err != nil {
		return fmt.Errorf("cannot preserve config ownership: %w", err)
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("cannot replace %s: %w", path, err)
	}
	return nil
}

func replaceFile(tmp, path string) error {
	if err := os.Rename(tmp, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows cannot rename over an existing file. This fallback is only used
	// by local tests; production is Linux and takes the atomic rename path.
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func restartSoarClient() error {
	out, err := exec.Command("systemctl", "restart", "soar-client").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart soar-client failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// warnOverrides catches the most common reason a changed JSON file appears to
// have no effect: variables left in mode.env are exported by the main wrapper
// and override the JSON values.
func warnOverrides(configPath string, listenChanged bool) {
	if filepath.Clean(configPath) != defaultAuthConfig {
		return
	}
	data, err := os.ReadFile("/etc/soar-client/mode.env")
	if err != nil {
		return
	}
	var found []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SOAR_USERNAME="):
			found = append(found, "SOAR_USERNAME")
		case strings.HasPrefix(line, "SOAR_PASSWORD="):
			found = append(found, "SOAR_PASSWORD")
		case listenChanged && strings.HasPrefix(line, "SOAR_LISTEN="):
			found = append(found, "SOAR_LISTEN")
		}
	}
	if len(found) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: /etc/soar-client/mode.env also sets %s.\n", strings.Join(found, ", "))
	fmt.Fprintln(os.Stderr, "         Those values override client.json. Remove them or update them too.")
}
