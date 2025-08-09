package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

const magic = "openssh-key-v1\x00"

const (
	FlagUP = 0x01 // user presence required
	FlagUV = 0x04 // user verification required
)

type openSSHEnvelope struct {
	CipherName   string
	KdfName      string
	KdfOpts      []byte
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type ed25519sk struct {
	PubKey      []byte
	Application string
	Flags       uint8
	KeyHandle   []byte
	Reserved    []byte
	Comment     string
	Rest        []byte `ssh:"rest"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	inPath, ops, showHelp, inPlace, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if showHelp {
		printUsage()
		return nil
	}
	if inPath == "" {
		printUsage()
		return errors.New("missing positional <keyfile> argument")
	}

	// Read file
	data, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("failed to read input file %q: %w", inPath, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("input file %q is empty", inPath)
	}

	// Decode PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from %q: input is not a valid PEM", inPath)
	}
	if len(block.Bytes) < len(magic) {
		return errors.New("invalid OpenSSH private key: too short")
	}
	if string(block.Bytes[:len(magic)]) != magic {
		return errors.New("invalid OpenSSH private key: missing openssh-key-v1 magic")
	}
	body := block.Bytes[len(magic):]

	// Parse envelope
	var env openSSHEnvelope
	if err := ssh.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("failed to parse OpenSSH envelope: %w", err)
	}
	if env.CipherName != "none" || env.KdfName != "none" {
		return fmt.Errorf("encrypted private keys are not supported (cipher=%q, kdf=%q)", env.CipherName, env.KdfName)
	}
	if env.NumKeys != 1 {
		return fmt.Errorf("unsupported number of keys in private file: %d (expected 1)", env.NumKeys)
	}

	// Parse private block
	var pk openSSHPrivateKey
	if err := ssh.Unmarshal(env.PrivKeyBlock, &pk); err != nil {
		return fmt.Errorf("failed to parse private key block: %w", err)
	}
	if pk.Check1 != pk.Check2 {
		return errors.New("private key block checkints mismatch (possibly corrupted input)")
	}
	if pk.Keytype != "sk-ssh-ed25519@openssh.com" {
		return fmt.Errorf("unsupported key type: %q (expected sk-ssh-ed25519@openssh.com)", pk.Keytype)
	}

	// Parse SK section
	var sk ed25519sk
	if err := ssh.Unmarshal(pk.Rest, &sk); err != nil {
		return fmt.Errorf("failed to parse sk section: %w", err)
	}
	oldFlags := sk.Flags

	// Apply ops
	if len(ops) > 0 {
		if err := applyFlagOps(&sk, ops); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr, "Info: no flag operations provided, keeping flags as-is (0x%02x)\n", sk.Flags)
	}

	// Reassemble
	newSK := ssh.Marshal(sk)
	newPriv := ssh.Marshal(openSSHPrivateKey{
		Check1:  pk.Check1,
		Check2:  pk.Check2,
		Keytype: pk.Keytype,
		Rest:    newSK,
	})
	env.PrivKeyBlock = newPriv
	newEnvelope := ssh.Marshal(env)
	final := append([]byte(magic), newEnvelope...)

	outBlock := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: final,
	}
	outBytes := pem.EncodeToMemory(outBlock)
	if outBytes == nil {
		return errors.New("failed to encode PEM to memory")
	}

	// Output
	if inPlace {
		if err := writeFileInPlace(inPath, outBytes); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Info: flags updated 0x%02x -> 0x%02x; written in-place to %s\n", oldFlags, sk.Flags, inPath)
	} else {
		if _, err := os.Stdout.Write(outBytes); err != nil {
			return fmt.Errorf("failed to write PEM to stdout: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Info: flags updated 0x%02x -> 0x%02x; written to stdout\n", oldFlags, sk.Flags)
	}

	return nil
}

func parseArgs(args []string) (inPath string, ops []string, showHelp bool, inPlace bool, err error) {
	var nonFlags []string
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			showHelp = true
		case a == "-i" || a == "--in-place":
			inPlace = true
		case strings.HasPrefix(a, "+") || strings.HasPrefix(a, "-"):
			switch strings.ToLower(a) {
			case "+uv", "-uv", "+up", "-up":
				ops = append(ops, a)
			default:
				return "", nil, false, false, fmt.Errorf("invalid flag %q; expected +uv, -uv, +up, -up, -i/--in-place, --help", a)
			}
		default:
			nonFlags = append(nonFlags, a)
		}
	}
	if len(nonFlags) > 1 {
		return "", nil, false, false, fmt.Errorf("too many positional arguments: %v (expected only <keyfile>)", nonFlags)
	}
	if len(nonFlags) == 1 {
		inPath = nonFlags[0]
	}
	return inPath, ops, showHelp, inPlace, nil
}

func applyFlagOps(sk *ed25519sk, ops []string) error {
	for _, op := range ops {
		switch strings.ToLower(op) {
		case "+uv":
			sk.Flags = sk.Flags | FlagUV
		case "-uv":
			sk.Flags = sk.Flags &^ FlagUV
		case "+up":
			sk.Flags = sk.Flags | FlagUP
		case "-up":
			sk.Flags = sk.Flags &^ FlagUP
		}
	}
	return nil
}

func writeFileInPlace(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	var mode os.FileMode = 0600
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode()
	}

	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set temp file mode: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("failed to fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to replace %q atomically: %w", path, err)
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  ssh-sk-rk-patcher [flags] <keyfile>

Flags:
  +uv            Enable user verification requirement
  -uv            Disable user verification requirement
  +up            Enable user presence requirement
  -up            Disable user presence requirement
  -i, --in-place Overwrite the <keyfile> atomically
  -h, --help     Show this help

Notes:
  - The <keyfile> must be an OpenSSH "OPENSSH PRIVATE KEY" file with key type sk-ssh-ed25519@openssh.com.
  - Encrypted private keys are not supported by this tool.
  - By default, the modified key is written to stdout; errors/logs go to stderr.
`)
}
