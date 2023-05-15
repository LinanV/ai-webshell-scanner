package core

import (
	"bytes"
	"compress/zlib"
	"math"
	"regexp"
)

const (
	RateAsValue = iota
	FuncAsValue
	ExistAsValue
	CompareAsValue
)

type CalculateFunc func(data string) float64
type Calculator struct {
	Weight          float64
	CalculateMethod int
	Coefficient     float64
	Func            CalculateFunc
}

func (c *Calculator) Uniformization(data string) float64 {
	value := float64(0)
	switch c.CalculateMethod {
	case RateAsValue:
		value = c.Func(data) * c.Coefficient * c.Weight
	case FuncAsValue:
		value = 1 / (1 + math.Pow(math.E, (c.Coefficient-4.0)-c.Func(data))) * c.Weight
	case ExistAsValue:
		if c.Func(data) > 0 {
			value = c.Weight * c.Coefficient
		}
	case CompareAsValue:
		if c.Func(data) > c.Coefficient {
			value = c.Weight
		}
	default:
		value = c.Func(data) * c.Weight
	}

	return value
}

var languageIC = &Calculator{
	Weight:          1,
	CalculateMethod: RateAsValue,
	Coefficient:     1,
	Func: func(data string) float64 {
		if data == "" {
			return 0
		}

		charCount := 0
		charCountMap := make(map[byte]int)
		dataBytes := []byte(data)
		totalChar := len(dataBytes)
		fc := float64(totalChar*(totalChar-1))
		if fc <= 0 {
			return 0
		}

		for _, b := range dataBytes {
			if _, ok := charCountMap[b]; ok {
				charCountMap[b] += 1
			} else {
				charCountMap[b] = 1
			}
		}

		for _, v := range charCountMap {
			charCount += v * (v - 1)
		}

		ic := float64(charCount) / fc
		return ic
	},
}

var entropy = &Calculator{
	Weight:          1,
	CalculateMethod: FuncAsValue,
	Coefficient:     6,
	Func: func(data string) float64 {
		if data == "" {
			return 0
		}

		entropy := float64(0)
		dataBytes := []byte(data)
		totalLength := 0
		charCountMap := make(map[byte]int)
		for _, b := range dataBytes {
			if b == ' ' {
				continue
			}
			totalLength += 1
			if _, ok := charCountMap[b]; ok {
				charCountMap[b] += 1
			} else {
				charCountMap[b] = 1
			}
		}

		if totalLength == 0 {
			return 0
		}

		for _, v := range charCountMap {
			px := float64(v) / float64(totalLength)
			if px > 0 {
				entropy += -px * math.Log2(px)
			}
		}
		return entropy
	},
}

var longestWord = &Calculator{
	Weight:          1,
	CalculateMethod: CompareAsValue,
	Coefficient:     256,
	Func: func(data string) float64 {
		if data == "" {
			return 0
		}
		longest := 0
		re := regexp.MustCompile(`[\s\n\r]`)
		words := re.Split(data, -1)
		for _, word := range words {
			length := len(word)
			if length > longest {
				longest = length
			}
		}
		return float64(longest)
	},
}

var signatureNasty = &Calculator{
	Weight:          1,
	CalculateMethod: ExistAsValue,
	Coefficient:     1,
	Func: func(data string) float64 {
		validRegex := regexp.MustCompile(`(?i)(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|pcntl|assert\(|system\(|shell)`)
		matches := validRegex.FindAllString(data, -1)
		matchesLength := len(matches)
		return float64(matchesLength)
	},
}

var useEval = &Calculator{
	Weight:          1,
	CalculateMethod: ExistAsValue,
	Coefficient:     1,
	Func: func(data string) float64 {
		validRegex := regexp.MustCompile(`(?i)(eval\(\$(\w|\d))`)
		matches := validRegex.FindAllString(data, -1)
		matchesLength := len(matches)
		return float64(matchesLength)
	},
}

var compression = &Calculator{
	Weight:          1,
	CalculateMethod: RateAsValue,
	Coefficient:     1,
	Func: func(data string) float64 {
		if data == "" {
			return 0
		}

		var buf bytes.Buffer
		writer := zlib.NewWriter(&buf)
		_, _ = writer.Write([]byte(data))
		_ = writer.Close()
		return float64(len(buf.String())) / float64(len(data))
	},
}

