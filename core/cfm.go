package core

import "regexp"

const (
	CFM = "cfm"
)

var cfm = &Plugin{
	Name:     CFM,
	Desc:     "A plugin that detects webshell of cfm type",
	Decoders: []Decoder{},
	Tags: []Tag{
		{Name: "cfm/execution", Regex: regexp.MustCompile(`(?i)(?:"?/c\s+"?'?#?cmd#?'?"?)`), Scored: 50},
	},
	Supports: []string{"cfm"},
}
