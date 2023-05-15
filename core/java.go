package core

import "regexp"

const (
	JAVA = "java"
)

var java = &Plugin{
	Name:     JAVA,
	Desc:     "A plugin that detects webshell of java type",
	Decoders: []Decoder{},
	Tags: []Tag{
		{Name: "java/execution", Regex: regexp.MustCompile(`(?i)(?:runtime\.exec\()`), Scored: 50},
		{Name: "java/one", Regex: regexp.MustCompile(`(?i)(request.getParameter\(|new java.io.FileOutputStream\()`), Scored: 14, Repeat: true},
	},
	Supports: []string{"jsp", "jspx", "java"},
}
