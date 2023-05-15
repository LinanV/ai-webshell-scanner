package main

import (
	"flag"
	"fmt"
	logger "github.com/golang/glog"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"wxel/core"
)

const (
	MaxSize           = 10 * 1024 * 1024
	EndSig            = "__WXX__"
	WebshellType      = "1"
	RegularType       = "0"
	WebshellTarget    = "/webshell/"
	defaultOutputFile = "./train.csv"
)

func walkDir(obj string, fileChan chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	err := filepath.WalkDir(obj, func(path string, d fs.DirEntry, err error) error {
		if info, err := d.Info(); err == nil && info.Size() < MaxSize && d.Type().IsRegular() {
			fileChan <- path
		}
		return nil
	})
	if err != nil {
		logger.Errorf("walk dir %s error: %v \n", obj, err)
		return
	}
}

func walk(obj string, fileChan chan string) {
	var wg sync.WaitGroup
	if f, err := os.Stat(obj); err != nil {
		logger.Errorf("scan object %s error: %v \n", obj, err)
	} else {
		if f.IsDir() {
			objs, _ := ioutil.ReadDir(obj)
			for _, o := range objs {
				if o.IsDir() {
					wg.Add(1)
					go walkDir(filepath.Join(obj, o.Name()), fileChan, &wg)
				} else if o.Mode().IsRegular() && o.Size() < MaxSize {
					fileChan <- filepath.Join(obj, o.Name())
				}
			}
		} else if f.Mode().IsRegular() && f.Size() < MaxSize {
			fileChan <- obj
		} else {
			logger.Errorf("invalid scan object: %s \n", obj)
		}
	}
	wg.Wait()
	fileChan <- EndSig
}

func generate_train_data(fileChan chan string, outputFile string) {
	fd, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		logger.Errorf("open file %s failed: %v", outputFile, err)
		return
	}

	defer func(fd *os.File) {
		_ = fd.Close()
	}(fd)

	plugins := core.GetPlugins()
	calculators := core.GetCalculators()

	for {
		select {
		case obj := <-fileChan:
			if obj == EndSig {
				return
			}

			output := RegularType
			if strings.Contains(obj, WebshellTarget) {
				output = WebshellType
			}

			if content, err := ioutil.ReadFile(obj); err != nil {
				logger.Errorf("read file %s error: %v", obj, err)
			} else {
				var param []string
				contentStr := string(content)
				_, t := core.CheckRegexMatches(plugins, contentStr, obj)
				param = append(param, fmt.Sprintf("%f", t))
				for _, calculator := range calculators {
					param = append(param, fmt.Sprintf("%f", calculator.Uniformization(contentStr)))
				}
				param = append(param, output)
				data := strings.Join(param, ", ") + "\n"
				logger.Info(data)
				_, err = fd.Write([]byte(data))
				if err != nil {
					logger.Warningf("write file %s error: %v", outputFile, err)
				}
			}
		}
	}
}

func main() {
	var obj string
	var output string
	flag.StringVar(&obj, "d", "", "scan file or directory")
	flag.StringVar(&output, "o", defaultOutputFile, "output file path")
	flag.Parse()

	fileChan := make(chan string)
	go walk(obj, fileChan)
	generate_train_data(fileChan, output)
}
