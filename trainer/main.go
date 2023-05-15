package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	deep "github.com/patrikeh/go-deep"
	"github.com/patrikeh/go-deep/training"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

const (
	outputFile = "module.json"
	// 可以调整一下参数使得模型更加准确
	seed      = 1684132245039910525
	learnRate = 0.05
	momentum  = 0.126
	decay     = 0.03
	trainNum  = 500
)

func get_traning_examples() training.Examples {
	f, err := os.Open("sample/train.csv")
	if err != nil {
		panic(err)
	}

	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	r := csv.NewReader(bufio.NewReader(f))

	var examples training.Examples
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		examples = append(examples, toExample(record))
	}
	return examples
}

func toExample(in []string) training.Example {
	elements := []float64{}
	for _, elm := range in {
		elm = strings.Trim(elm, " ")
		if elm == "NaN" {
			elm = "0"
		}
		res, err := strconv.ParseFloat(elm, 64)
		if err != nil {
			panic(err)
		}
		elements = append(elements, res)
	}

	last_index := len(elements) - 1
	return training.Example{
		Response: []float64{elements[last_index]},
		Input:    elements[:last_index],
	}
}

func main() {
	rand.Seed(seed)

	data := get_traning_examples()

	n := deep.NewNeural(&deep.Config{
		Inputs:     7,
		Layout:     []int{7, 7, 1},
		Activation: deep.ActivationSigmoid,
		Mode:       deep.ModeMultiLabel,
		Weight:     deep.NewNormal(1.0, 0.0),
		Bias:       true,
	})

	optimizer := training.NewSGD(learnRate, momentum, decay, true)
	trainer := training.NewTrainer(optimizer, 50)
	trains, heldout := data.Split(0.8)
	trainer.Train(n, trains, heldout, trainNum)

	b, e := json.Marshal(n)
	if e != nil {
		panic(e)
	}
	_ = ioutil.WriteFile(outputFile, b, 0o644)

}
