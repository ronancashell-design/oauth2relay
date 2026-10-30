// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"oauth2relay.com/oauth2relay/v2/config"
)

// ---------------- Command line ----------------

const defaultConfigFile = "config.json"

// cliOptions holds the command-line flags.
type cliOptions struct {
	configFile  string
	checkConfig bool
	logLevel    string
	logFormat   string
	showVersion bool
	showHelp    bool
}

// parseArgs parses the command line (without the program name). Flags may
// come before or after the config file, which can also be given with
// --config. Both -flag and --flag forms are accepted.
func parseArgs(args []string, stderr io.Writer) (*cliOptions, error) {
	opts := &cliOptions{}
	fs := flag.NewFlagSet("oauth2relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	fs.StringVar(&opts.configFile, "config", "", "")
	fs.BoolVar(&opts.checkConfig, "check-config", false, "")
	fs.StringVar(&opts.logLevel, "log-level", "", "")
	fs.StringVar(&opts.logFormat, "log-format", "", "")
	fs.BoolVar(&opts.showVersion, "version", false, "")
	fs.BoolVar(&opts.showVersion, "v", false, "")

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				opts.showHelp = true
				return opts, nil
			}
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}

	switch {
	case len(positional) > 1:
		return nil, fmt.Errorf("only one config file may be given, got %q", positional)
	case len(positional) == 1 && opts.configFile != "":
		return nil, fmt.Errorf("config file given both as --config %q and as %q", opts.configFile, positional[0])
	case len(positional) == 1:
		opts.configFile = positional[0]
	case opts.configFile == "":
		opts.configFile = defaultConfigFile
	}
	return opts, nil
}

// apply sets the configuration fields that flags override.
func (opts *cliOptions) apply(cfg *config.Config) {
	if opts.logLevel != "" {
		cfg.LogLevel = opts.logLevel
	}
	if opts.logFormat != "" {
		cfg.LogFormat = opts.logFormat
	}
}
