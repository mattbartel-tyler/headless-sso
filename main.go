package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gen2brain/beeep"
	"github.com/git-lfs/go-netrc/netrc"
	"github.com/theckman/yacspin"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
)

// Time before MFA step times out
const MFA_TIMEOUT = 30

var cfg = yacspin.Config{
	Frequency:         100 * time.Millisecond,
	CharSet:           yacspin.CharSets[59],
	Suffix:            "AWS SSO Signing in: ",
	SuffixAutoColon:   false,
	Message:           "",
	StopCharacter:     "✓",
	StopFailCharacter: "✗",
	StopMessage:       "Logged in successfully",
	StopFailMessage:   "Log in failed",
	StopColors:        []string{"fgGreen"},
}

var spinner, _ = yacspin.New(cfg)

func main() {
	spinner.Start()

	// get sso url from stdin
	url := getURL()
	// start aws sso login
	ssoLogin(url)

	spinner.Stop()
	time.Sleep(1 * time.Second)
}

// returns sso url from stdin.
func getURL() string {
	spinner.Message("reading url from stdin")

	scanner := bufio.NewScanner(os.Stdin)
	url := ""
	for url == "" {
		scanner.Scan()
		t := scanner.Text()
		r, _ := regexp.Compile("^https.*user_code=([A-Z]{4}-?){2}")

		if r.MatchString(t) {
			url = t
		}
	}

	return url
}

// get aws credentials from netrc file
func getCredentials() (string, string, error) {
	spinner.Message("fetching credentials from .netrc")

	usr, _ := user.Current()
	f, err := netrc.ParseFile(filepath.Join(usr.HomeDir, ".netrc"))
	if err != nil {
		return "", "", fmt.Errorf(".netrc file not found in HOME directory")
	}

	username := f.FindMachine("headless-sso", "").Login
	passphrase := f.FindMachine("headless-sso", "").Password

	return username, passphrase, nil
}

func getCredentialsBitwarden() (string, string, error) {
	item := os.Getenv("AWS_HEADLESS_SSO_BW_SECRET")
	if len(item) == 0 {
		return "", "", nil
	}

	spinner.Message("fetching credentials from bitwarden")

	usernameCmd := exec.Command("bw", "get", "username", item)
	usernameOut, err := usernameCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed getting username from bitwarden: %w", err)
	}
	username := strings.TrimSpace(string(usernameOut))

	passwordCmd := exec.Command("bw", "get", "password", item)
	passwordOut, err := passwordCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed getting password from bitwarden: %w", err)
	}
	password := strings.TrimSpace(string(passwordOut))

	return username, password, nil
}

// login with hardware MFA
func ssoLogin(url string) {
	var username, passphrase string
	var err error
	if len(os.Getenv("AWS_HEADLESS_SSO_BW_SECRET")) > 0 {
		if len(os.Getenv("BW_SESSION")) == 0 {
			logFailureAndExit(`BW_SESSION is not set. Try running 'export BW_SESSION="$(bw login --raw)"'`, url)
		}

		username, passphrase, err = getCredentialsBitwarden()
		if err != nil {
			logFailureAndExit(err.Error(), url)
		}
	} else {
		username, passphrase, err = getCredentials()
		if err != nil {
			logFailureAndExit(err.Error(), url)
		}
	}

	spinner.Message(color.MagentaString("init headless-browser \n"))
	spinner.Pause()

	// l := launcher.New().Headless(false).Devtools(true)
	// defer l.Cleanup()
	// controlUrl := l.MustLaunch()
	// browser := rod.New().ControlURL(controlUrl).MustConnect().Trace(false)

	browser := rod.New().MustConnect().Trace(false)
	defer browser.MustClose()

	var page *rod.Page

	err = rod.Try(func() {
		page = browser.MustPage(url)

		// authorize
		spinner.Unpause()
		spinner.Message("logging in")
		page.MustElementR("button", "Next").MustWaitEnabled().MustPress()

		// sign-in
		page.Race().ElementR("button", "Allow").MustHandle(func(e *rod.Element) {
		}).Element("#awsui-input-0").MustHandle(func(e *rod.Element) {
			signIn(*page, username, passphrase)
			// mfa required step
			mfa()
		}).MustDo()

		page.Timeout(MFA_TIMEOUT*time.Second).MustElementR("button", "Confirm and continue").MustWaitEnabled().MustClick()
		page.Timeout(MFA_TIMEOUT*time.Second).MustElementR("button", "Allow access").MustWaitEnabled().MustClick()
		page.Timeout(MFA_TIMEOUT*time.Second).MustElementR(".awsui-context-alert", "Request approved").MustWaitLoad()
	})

	if errors.Is(err, context.DeadlineExceeded) {
		logFailureAndExit("Timed out waiting for MFA", url)
	} else if err != nil {
		logFailureAndExit(err.Error(), url)
	}
}

// executes aws sso signin step
func signIn(page rod.Page, username, passphrase string) {
	page.MustElement("#awsui-input-0").MustInput(username).MustPress(input.Enter)
	page.MustElement("#awsui-input-1").MustInput(passphrase).MustPress(input.Enter)
}

// TODO: allow user to enter MFA Code
func mfa() {
	_ = beeep.Notify("headless-sso", "Touch U2F device to proceed with authenticating AWS SSO", "")
	_ = beeep.Beep(beeep.DefaultFreq, beeep.DefaultDuration)

	spinner.Message(color.YellowString("Touch U2F"))
}

// print error message and exit
func logFailureAndExit(errorMsg, url string) {
	spinner.StopFailMessage(color.RedString("Login failed error - " + errorMsg))
	spinner.StopFail()

	if len(url) > 0 {
		fmt.Printf("Try logging in manually at: %s\n", url)
	}

	os.Exit(1)
}
