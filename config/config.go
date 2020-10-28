package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"
)

type Config struct {
	GNodeB struct {
		ControlIF struct {
			Ip   string `yaml: "ip"`
			Port int    `yaml: "port"`
		} `yaml: "controlif"`
		DataIF struct {
			Ip   string `yaml: "ip"`
			Port int    `yaml: "port"`
		} `yaml: "dataif"`
	} `yaml:"gnodeb"`
	Ue struct {
		Imsi string `yaml: "imsi"`
		Key  string `yaml: "key"`
		Opc  string `yaml: "opc"`
		Amf  string `yaml: "amf"`
	} `yaml:"ue"`
	AMF struct {
		Ip   string `yaml: "ip"`
		Port int    `yaml: "port"`
	} `yaml:"amfif"`
	UPF struct {
		Ip   string `yaml: "ip"`
		Port int    `yaml: "port"`
	} `yaml:"upfif"`
}

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func GetConfig() (Config, error) {
	var cfg = Config{}
	Ddir := rootDir()
	configPath, err := filepath.Abs(Ddir + "/config/config.yml")
	fmt.Println(configPath)
	if err != nil {
		return Config{}, nil
	}
	file, err := ioutil.ReadFile(configPath)
	err = yaml.Unmarshal([]byte(file), &cfg)
	if err != nil {
		return Config{}, nil
	}

	return cfg, nil
}