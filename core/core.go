package core

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type BaseFunc func(in []byte, args ...interface{}) ([]byte, error)

type Action struct {
	Func      BaseFunc
	Arguments []interface{}
}

type Decoder struct {
	Name              string
	Regex             *regexp.Regexp
	DataFilter        *regexp.Regexp
	PreDecodeActions  []Action
	PostDecodeActions []Action
	Functions         []BaseFunc
}

type Tag struct {
	Name   string
	Regex  *regexp.Regexp
	Scored float64 // 计分
	Repeat bool    // 标记规则是否需要重复计数
}

type Plugin struct {
	Name     string
	Desc     string
	Decoders []Decoder
	Tags     []Tag
	Supports []string
}

var DecodeBase64 BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(in))
}

var GzInflate BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	return ioutil.ReadAll(flate.NewReader(bytes.NewReader(in)))
}

var UrlDecode BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	decodeString, err := url.QueryUnescape(string(in))
	if err != nil {
		return nil, err
	}

	b := []byte(decodeString)
	return b, nil
}

var StringReplace BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("[StringReplace] Bad number of main arguments: %v\n", args)
	}

	if reflect.TypeOf(args[0]).Kind() != reflect.String {
		return nil, fmt.Errorf("[StringReplace] Bad type found with first arguments: %v\n", args)
	}

	if reflect.TypeOf(args[1]).Kind() != reflect.String {
		return nil, fmt.Errorf("[StringReplace] Bad type found with second arguments: %v\n", args)
	}

	if reflect.TypeOf(args[2]).Kind() != reflect.Int {
		return nil, fmt.Errorf("[StringReplace] Bad type found with third arguments: %v\n", args)
	}

	cleanedItem := strings.Replace(string(in), args[0].(string), args[1].(string), args[2].(int))

	return []byte(cleanedItem), nil
}

var StringReplaceWithRegex BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("[StringReplaceWithRegex] Bad number of main arguments: %v\n", args)
	}

	if reflect.TypeOf(args[0]).Kind() != reflect.String {
		return nil, fmt.Errorf("[StringReplaceWithRegex] Bad type found with first arguments: %v\n", args)
	}

	if reflect.TypeOf(args[1]).Kind() != reflect.String {
		return nil, fmt.Errorf("[StringReplaceWithRegex] Bad type found with second arguments: %v\n", args)
	}

	regexItem, err := regexp.Compile(args[0].(string))
	if err != nil {
		return nil, err
	}

	res := regexItem.ReplaceAllString(string(in), args[1].(string))
	return []byte(res), nil
}

var CharDecode BaseFunc = func(in []byte, args ...interface{}) ([]byte, error) {
	var cleanedItem []string
	items := strings.Split(string(in), "|")
	for _, i := range items {
		getInt, err := strconv.Atoi(i)
		if err != nil {
			continue
		}
		ch := rune(getInt)
		cleanedItem = append(cleanedItem, fmt.Sprintf("%c", ch))
	}

	if len(cleanedItem) == 0 {
		return in, nil
	}

	joinedItems := strings.Join(cleanedItem, "")
	return []byte(joinedItems), nil
}

func GetPlugins() []*Plugin {
	return []*Plugin{generic, asp, cfm, java, php}
}

func GetCalculators() []*Calculator {
	return []*Calculator{languageIC, entropy, longestWord, signatureNasty, useEval, compression}
}