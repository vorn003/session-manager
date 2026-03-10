package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"crypto/md5"
	"github.com/manifoldco/promptui"
	"gopkg.in/yaml.v3"
)

// Version is set at build time using -ldflags
var Version = "dev"

const quitLabel = "\u2717 Quit" // ✗
const backLabel = "\u2190 Back" // ←

// httpGet wraps http.Get for update functionality
func httpGet(url string) (*http.Response, error) {
	return http.Get(url)
}

// discardWriteCloser wraps io.Discard to satisfy io.WriteCloser
type discardWriteCloser struct{}

func (d discardWriteCloser) Write(p []byte) (int, error) {
	return io.Discard.Write(p)
}
func (d discardWriteCloser) Close() error { return nil }

// bellFilter filters out BEL ('\a') characters from the output stream.
type bellFilter struct {
	w io.Writer
}

// Close implements io.Closer for bellFilter, but does nothing.
func (b bellFilter) Close() error {
	return nil
}

func (b bellFilter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Remove all BEL characters
	filtered := make([]byte, 0, len(p))
	for _, c := range p {
		if c != '\a' {
			filtered = append(filtered, c)
		}
	}
	// Write the filtered bytes to the underlying writer.
	n, err := b.w.Write(filtered)
	// We return the length of the original slice (as Write contract), but if there's an error,
	// return that error. Many callers expect n == len(p); here we return the number of bytes
	// successfully "accepted" from the original slice; most callers ignore the exact n on success.
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// Config structures

type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Command     string `yaml:"command,omitempty"`
}

type Project struct {
	Name    string   `yaml:"name"`
	Servers []Server `yaml:"servers"`
}

type Config struct {
	GlobalCommand    string    `yaml:"global_command"`
	ExitOnDisconnect *bool     `yaml:"exit_on_disconnect"`
	Projects         []Project `yaml:"projects"`
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	// Handle --help, --update, --version
	args := os.Args[1:]
	if len(args) > 0 {
		if args[0] == "--help" {
			fmt.Printf(`SSHMenu - Interactive SSH launcher
			
Version: %s
Usage:
	sshmenu [search]
	sshmenu --help         Show this help message
	sshmenu --update       Update to latest release from GitHub
	sshmenu --version      Show version
`, Version)
			os.Exit(0)
		}
		if args[0] == "--version" {
			fmt.Println(Version)
			os.Exit(0)
		}
		if args[0] == "--update" {
			// Download latest release from GitHub and replace current binary
			updateURL := "https://github.com/vorn003/SSHMenu/releases/latest/download/sshmenu_linux_amd64"
			exePath, err := os.Executable()
			if err != nil {
				fmt.Println("Error determining executable path:", err)
				os.Exit(1)
			}
			// Download to a temporary file in the same directory as the executable
			exeDir := exePath
			if idx := strings.LastIndex(exePath, string(os.PathSeparator)); idx != -1 {
				exeDir = exePath[:idx]
			}
			tmpFile := exeDir + string(os.PathSeparator) + ".sshmenu_update_tmp"
			fmt.Println("Downloading latest release...")
			resp, err := httpGet(updateURL)
			if err != nil {
				fmt.Println("Download failed:", err)
				os.Exit(1)
			}
			defer resp.Body.Close()
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") {
				fmt.Println("Error: Downloaded file is HTML, not a binary. Check the release URL or authentication.")
				os.Exit(2)
			}
			out, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				fmt.Println("Error creating temporary file for update:", err)
				os.Exit(1)
			}
			defer out.Close()
			_, err = io.Copy(out, resp.Body)
			if err != nil {
				fmt.Println("Error writing update:", err)
				os.Exit(1)
			}
			// Compare md5sum of tempfile and current binary
			md5sum := func(path string) (string, error) {
				f, err := os.Open(path)
				if err != nil {
					return "", err
				}
				defer f.Close()
				h := md5.New()
				if _, err := io.Copy(h, f); err != nil {
					return "", err
				}
				return fmt.Sprintf("%x", h.Sum(nil)), nil
			}
			tmpSum, err := md5sum(tmpFile)
			if err != nil {
				fmt.Println("Error computing md5sum for tempfile:", err)
				os.Exit(1)
			}
			exeSum, err := md5sum(exePath)
			if err != nil {
				fmt.Println("Error computing md5sum for executable:", err)
				os.Exit(1)
			}
			if tmpSum != exeSum {
				// Move the temporary file to the executable location
				err = os.Rename(tmpFile, exePath)
				if err != nil {
					fmt.Println("Error replacing executable:", err)
					os.Exit(1)
				}
				fmt.Printf("Update complete.")
				os.Exit(0)
			} else {
				fmt.Printf("No update needed, already on latest version: %s\n", Version)
				os.Remove(tmpFile)
				os.Exit(0)
			}
		}
	}

	// Prefer ~/.config/sshmenu/sshmenu.yaml if it exists, else use next to binary
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Error determining user home directory:", err)
		os.Exit(1)
	}
	userConfigPath := homeDir + string(os.PathSeparator) + ".config" + string(os.PathSeparator) + "sshmenu" + string(os.PathSeparator) + "sshmenu.yaml"
	configPath := userConfigPath
	if _, err := os.Stat(userConfigPath); os.IsNotExist(err) {
		exePath, err := os.Executable()
		if err != nil {
			fmt.Println("Error determining executable path:", err)
			os.Exit(1)
		}
		exeDir := exePath
		if idx := strings.LastIndex(exePath, string(os.PathSeparator)); idx != -1 {
			exeDir = exePath[:idx]
		}
		configPath = exeDir + string(os.PathSeparator) + "sshmenu.yaml"
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Println("Error loading config:", err)
		os.Exit(1)
	}

	// Clear the terminal screen before showing the menu
	fmt.Print("\033[2J\033[H")

	// Create a bell-filtered writer that wraps the real stdout
	filteredStdout := bellFilter{w: os.Stdout}

	searchString := ""
	// Support search parameter from command line (ignore --help/--update)
	if len(args) > 0 && args[0] != "--help" && args[0] != "--update" {
		searchString = strings.Join(args, " ")
	}

	for {
		// Reload config for inplace update
		cfg, err = loadConfig(configPath)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}

		if searchString != "" {
			// Flat filtered list
			flatServers := []Server{}
			for _, p := range cfg.Projects {
				for _, s := range p.Servers {
					if strings.Contains(strings.ToLower(s.Name), strings.ToLower(searchString)) || strings.Contains(strings.ToLower(s.Description), strings.ToLower(searchString)) {
						flatServers = append(flatServers, s)
					}
				}
			}
			if len(flatServers) == 0 {
				fmt.Println("No servers found matching:", searchString)
				return
			}
			serverNames := []string{}
			for _, s := range flatServers {
				serverNames = append(serverNames, s.Name+" - "+s.Description)
			}
			serverNames = append(serverNames, quitLabel)

			// Select server from flat list
			serverPrompt := promptui.Select{
				Label:       "Select Server",
				Items:       serverNames,
				HideHelp:    true,
				HideSelected: true,
				Size:        50,
				Stdout:      filteredStdout,
			}
			sidx, sresult, err := serverPrompt.Run()
			fmt.Print("\r\033[K")
			if err == promptui.ErrInterrupt || err == promptui.ErrEOF {
				fmt.Println("Exiting.")
				return
			}
			if err != nil {
				fmt.Println("Prompt failed:", err)
				return
			}
			if sresult == quitLabel {
				fmt.Println("Exiting.")
				return
			}
			// Only proceed if a real server was selected
			if sidx < 0 || sidx >= len(flatServers) {
				return
			}
			server := flatServers[sidx]
			cmdStr := server.Command
			if cmdStr == "" {
				cmdStr = cfg.GlobalCommand
				cmdStr = replaceServer(cmdStr, server.Name)
			}
			fmt.Println("Running:", cmdStr)
			cmd := exec.Command("bash", "-c", cmdStr)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			if err := cmd.Run(); err != nil {
				fmt.Println("Command failed:", err)
			}
			return
		} else {
			// Two-step UI: project → server
			projectNames := []string{}
			for _, p := range cfg.Projects {
				projectNames = append(projectNames, p.Name)
			}
			projectNames = append(projectNames, quitLabel)

			projectPrompt := promptui.Select{
				Label:        "Select Project (↑/↓ navigate, ✗ to quit)",
				Items:        projectNames,
				HideHelp:     true,
				HideSelected: true,
				Size:         50,
				Stdout:       filteredStdout,
			}
			pidx, presult, err := projectPrompt.Run()
			fmt.Print("\r\033[K")
			if err == promptui.ErrInterrupt || err == promptui.ErrEOF {
				fmt.Println("Exiting.")
				return
			}
			if err != nil {
				fmt.Println("Prompt failed:", err)
				return
			}
			if presult == quitLabel {
				fmt.Println("Exiting.")
				return
			}
			// Only proceed if a real project was selected
			if pidx < 0 || pidx >= len(cfg.Projects) {
				return
			}
			project := cfg.Projects[pidx]
			serverNames := []string{}
			for _, s := range project.Servers {
				serverNames = append(serverNames, s.Name+" - "+s.Description)
			}
			serverNames = append(serverNames, backLabel)
			for {
				serverPrompt := promptui.Select{
					Label:        "Select Server",
					Items:        serverNames,
					HideHelp:     true,
					HideSelected: true,
					Size:         50,
					Stdout:       filteredStdout,
				}
				sidx, sresult, err := serverPrompt.Run()
				fmt.Print("\r\033[K")
				if err == promptui.ErrInterrupt || err == promptui.ErrEOF {
					fmt.Println("Exiting.")
					return
				}
				if err != nil {
					fmt.Println("Prompt failed:", err)
					break
				}
				if sresult == backLabel {
					goto ProjectSelect
				}
				// Only proceed if a real server was selected
				if sidx < 0 || sidx >= len(project.Servers) {
					continue
				}
				server := project.Servers[sidx]
				cmdStr := server.Command
				if cmdStr == "" {
					cmdStr = cfg.GlobalCommand
					cmdStr = replaceServer(cmdStr, server.Name)
				}
				fmt.Println("Running:", cmdStr)
				cmd := exec.Command("bash", "-c", cmdStr)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Stdin = os.Stdin
				if err := cmd.Run(); err != nil {
					fmt.Println("Command failed:", err)
				}
				if cfg.ExitOnDisconnect == nil || *cfg.ExitOnDisconnect {
					return
				}
			}
			// After server selection, exit
			return
		ProjectSelect:
			// Restart project selection loop
			continue
		}
	}
}

func replaceServer(template, server string) string {
	return stringReplace(template, "{server}", server)
}

func stringReplace(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}
