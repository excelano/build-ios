// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const api = "https://api.appstoreconnect.apple.com/v1/"

var notIdentifier = regexp.MustCompile(`[^A-Za-z0-9_]`)

type item struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Attributes    map[string]any `json:"attributes"`
	Relationships map[string]struct {
		Data json.RawMessage `json:"data"`
	} `json:"relationships"`
}

type page struct {
	Data     []item `json:"data"`
	Included []item `json:"included"`
	Links    struct {
		Next string `json:"next"`
	} `json:"links"`
}

type ref struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type target struct {
	name     string
	bundleID string
	team     string
}

func (i item) str(key string) string {
	s, _ := i.Attributes[key].(string)
	return s
}

func main() {
	bundle := flag.String("bundle", "", "the app's bundle id; targets under it are signed")
	cert := flag.String("cert", "", "the runner's Distribution certificate, DER")
	settings := flag.String("settings", "", "the output of xcodebuild -showBuildSettings -json")
	key := flag.String("key", "", "the App Store Connect API key, .p8")
	keyID := flag.String("key-id", "", "the API key's id")
	issuer := flag.String("issuer", "", "the API key's issuer id")
	xcconfig := flag.String("xcconfig", "", "where to write the signing xcconfig")
	plist := flag.String("export-options", "", "where to write the export options plist")
	flag.Parse()
	for name, v := range map[string]string{"bundle": *bundle, "cert": *cert, "settings": *settings, "key": *key, "key-id": *keyID, "issuer": *issuer, "xcconfig": *xcconfig, "export-options": *plist} {
		if v == "" {
			fail(fmt.Errorf("-%s is required", name))
		}
	}
	if err := run(*bundle, *cert, *settings, *key, *keyID, *issuer, *xcconfig, *plist); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "signing:", err)
	os.Exit(1)
}

func run(bundle, certPath, settingsPath, keyPath, keyID, issuer, xcconfigPath, plistPath string) error {
	targets, err := readTargets(settingsPath, bundle)
	if err != nil {
		return err
	}
	der, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	token, err := mintToken(keyPath, keyID, issuer)
	if err != nil {
		return err
	}
	profiles, err := activeProfiles(token, der)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	var conf, mapping strings.Builder
	fmt.Fprintf(&conf, "CODE_SIGN_STYLE = Manual\nCODE_SIGN_IDENTITY = Apple Distribution\nDEVELOPMENT_TEAM = %s\n", targets[0].team)
	conf.WriteString("PROVISIONING_PROFILE_SPECIFIER = $(BUILD_IOS_PROFILE_$(PRODUCT_BUNDLE_IDENTIFIER:c99extidentifier))\n")
	for _, t := range targets {
		p, ok := profiles[t.bundleID]
		if !ok {
			return fmt.Errorf("no active App Store profile for %s lists the runner's certificate; run provision-appstore in the app's repo", t.bundleID)
		}
		content, err := base64.StdEncoding.DecodeString(p.str("profileContent"))
		if err != nil {
			return fmt.Errorf("%s: %w", p.str("name"), err)
		}
		for _, dir := range []string{"Library/MobileDevice/Provisioning Profiles", "Library/Developer/Xcode/UserData/Provisioning Profiles"} {
			full := filepath.Join(home, dir)
			if err := os.MkdirAll(full, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(full, p.str("uuid")+".mobileprovision"), content, 0o644); err != nil {
				return err
			}
		}
		fmt.Printf("profile %s (%s) for %s, expires %s\n", p.str("name"), p.str("uuid"), t.bundleID, p.str("expirationDate"))
		fmt.Fprintf(&conf, "BUILD_IOS_PROFILE_%s = %s\n", notIdentifier.ReplaceAllString(t.bundleID, "_"), p.str("uuid"))
		fmt.Fprintf(&mapping, "<key>%s</key><string>%s</string>", t.bundleID, p.str("uuid"))
	}
	if err := os.WriteFile(xcconfigPath, []byte(conf.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(plistPath, []byte(exportOptions(targets[0].team, mapping.String())), 0o644)
}

func exportOptions(team, mapping string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>method</key><string>app-store-connect</string>
<key>destination</key><string>export</string>
<key>signingStyle</key><string>manual</string>
<key>signingCertificate</key><string>Apple Distribution</string>
<key>teamID</key><string>` + team + `</string>
<key>provisioningProfiles</key><dict>` + mapping + `</dict>
<key>manageAppVersionAndBuildNumber</key><false/>
<key>uploadSymbols</key><true/>
</dict></plist>
`
}

func readTargets(path, bundle string) ([]target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var settings []struct {
		Target   string            `json:"target"`
		Settings map[string]string `json:"buildSettings"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []target
	seen := map[string]bool{}
	for _, s := range settings {
		id := s.Settings["PRODUCT_BUNDLE_IDENTIFIER"]
		if id != bundle && !strings.HasPrefix(id, bundle+".") {
			continue
		}
		if s.Settings["WRAPPER_EXTENSION"] == "xctest" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, target{name: s.Target, bundleID: id, team: s.Settings["DEVELOPMENT_TEAM"]})
	}
	if !seen[bundle] {
		return nil, fmt.Errorf("no target has the bundle id %s", bundle)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bundleID < out[j].bundleID })
	if out[0].team == "" {
		return nil, fmt.Errorf("the target %s sets no DEVELOPMENT_TEAM", out[0].name)
	}
	return out, nil
}

func activeProfiles(token string, der []byte) (map[string]item, error) {
	out := map[string]item{}
	next := api + "profiles?" + url.Values{
		"filter[profileType]":  {"IOS_APP_STORE"},
		"filter[profileState]": {"ACTIVE"},
		"include":              {"bundleId,certificates"},
		"limit":                {"200"},
		"limit[certificates]":  {"50"},
	}.Encode()
	for next != "" {
		var p page
		if err := get(token, next, &p); err != nil {
			return nil, err
		}
		bundles := map[string]string{}
		ours := map[string]bool{}
		for _, inc := range p.Included {
			switch inc.Type {
			case "bundleIds":
				bundles[inc.ID] = inc.str("identifier")
			case "certificates":
				content, err := base64.StdEncoding.DecodeString(inc.str("certificateContent"))
				ours[inc.ID] = err == nil && bytes.Equal(content, der)
			}
		}
		for _, d := range p.Data {
			var b ref
			if err := json.Unmarshal(d.Relationships["bundleId"].Data, &b); err != nil {
				continue
			}
			var certs []ref
			if err := json.Unmarshal(d.Relationships["certificates"].Data, &certs); err != nil {
				continue
			}
			listed := false
			for _, c := range certs {
				listed = listed || ours[c.ID]
			}
			id := bundles[b.ID]
			if listed && id != "" && d.str("expirationDate") > out[id].str("expirationDate") {
				out[id] = d
			}
		}
		next = p.Links.Next
	}
	return out, nil
}

func get(token, link string, out any) error {
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("App Store Connect answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

func mintToken(path, keyID, issuer string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s is not PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New(path + " is not an EC key")
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": issuer, "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(), "aud": "appstoreconnect-v1"})
	signing := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
