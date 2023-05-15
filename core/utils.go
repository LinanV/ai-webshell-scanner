package core

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
)

func sha256HashString(data []byte) string {
	h := sha256.New()
	h.Write(data)
	hash := fmt.Sprintf("%x", h.Sum(nil))
	return hash
}

func runActionFunctions(functions []Action, rawBytes []byte) ([]byte, bool, error) {
	if len(functions) == 0 {
		return rawBytes, false, nil
	}

	oHash := sha256HashString(rawBytes)

	for _, f := range functions {
		decoded, err := f.Func(rawBytes, f.Arguments...)
		if err != nil {
			return rawBytes, false, err
		}
		rawBytes = decoded
	}

	changed := false
	nHash := sha256HashString(rawBytes)
	if oHash != nHash {
		changed = true
	}

	return rawBytes, changed, nil
}

func runDecodingFunctions(functions []BaseFunc, rawBytes []byte) ([]byte, error) {
	for _, f := range functions {
		decoded, err := f(rawBytes)
		if len(decoded) == 0 {
			return rawBytes, nil
		}

		if err != nil {
			return rawBytes, err
		}
		rawBytes = decoded
	}

	return rawBytes, nil
}

func hasElement(src []string, dst string) bool {
	for _, elm := range src {
		if elm == dst {
			return true
		}
	}

	return false
}

func guessFileType(filename, content string) string {
	fileExt := ""
	if strings.Index(filename, ".") >= 0 {
		fileSplits := strings.Split(filename, ".")
		fileExt = fileSplits[len(fileSplits)-1]
	}
	if strings.HasPrefix(content, "<?php") {
		fileExt = "php"
	} else if strings.HasPrefix(content, "#!/usr/bin/perl") {
		fileExt = "pl"
	} else if strings.HasPrefix(content, "<%@ Language=") {
		fileExt = "asp"
	} else if strings.HasPrefix(content, "#!/usr/bin/python") || strings.HasPrefix(content, "#!/usr/bin/env python") {
		fileExt = "py"
	} else if strings.HasPrefix(content, "#!/usr/bin/sh") || strings.HasPrefix(content, "#!/usr/bin/env sh") {
		fileExt = "sh"
	} else if strings.HasPrefix(content, "#!/usr/bin/bash") || strings.HasPrefix(content, "#!/usr/bin/env bash") {
		fileExt = "sh"
	}
	return fileExt
}

func CheckRegexMatches(plugins []*Plugin, content string, filename string) (map[string]int32, float64) {
	fileMatches := make(map[string]int32)
	maxLoop := 10000
	dataChan := make(chan string, maxLoop)
	dataChan <- content
	count := 1
	matchValue := float64(0)
	fileType := guessFileType(filename, content)
	for data := range dataChan {
		for _, plugin := range plugins {
			if len(plugin.Supports) > 0 && !hasElement(plugin.Supports, fileType) {
				continue
			}
			for _, ti := range plugin.Tags {
				tagMatches := ti.Regex.FindAllString(data, -1)
				if len(tagMatches) == 0 {
					continue
				}

				p := float64(1)
				for _, tm := range tagMatches {
					if tm == "" || len(tm) > 256 {
						continue
					}

					if !ti.Repeat {
						if _, ok := fileMatches[tm]; ok {
							fileMatches[tm] = fileMatches[tm] + 1
							p = float64(fileMatches[tm])*0.002 + p
						} else {
							fileMatches[tm] = 1
						}
					}
				}
				matchValue += ti.Scored * p
			}
			for _, tr := range plugin.Decoders {
				obfuscateMatches := tr.Regex.FindAllString(data, -1)
				if len(obfuscateMatches) == 0 {
					continue
				}
				for _, om := range obfuscateMatches {
					filters := tr.DataFilter.FindAllString(om, -1)
					if len(filters) == 0 {
						continue
					}

					for _, filterMatched := range filters {
						changedBytes, _, err := runActionFunctions(tr.PreDecodeActions, []byte(filterMatched))
						if err != nil {
							fmt.Printf("pre runActionFunctions error : %v\n", err)
							continue
						}

						decoded, err := runDecodingFunctions(tr.Functions, changedBytes)
						if err != nil || len(decoded) == 0 || om == string(decoded) {
							continue
						} else {
							postDecoded, changed, err := runActionFunctions(tr.PostDecodeActions, decoded)
							if err != nil {
								continue
							}

							if changed && count <= maxLoop {
								dataChan <- string(postDecoded)
								count++
							}

							if count <= maxLoop {
								dataChan <- string(decoded)
								count++
							}
						}
					}
				}
			}
		}

		if len(dataChan) == 0 {
			close(dataChan)
			break
		}
	}

	return fileMatches, math.Min(matchValue, 100)
}
