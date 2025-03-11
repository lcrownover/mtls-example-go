package server

import (
	"fmt"
	"os"
)

func InitializeServer(basePath string) error {
	exists, err := DataDirExists(basePath)
	if err != nil {
		return fmt.Errorf("failed to check if data directory exists: %v", err)
	}
	if !exists {
		err := CreateDataDir(basePath)
		if err != nil {
			return fmt.Errorf("failed to create data directories: %v", err)
		}
	}
	return nil
}

func DataDirExists(basePath string) (bool, error) {
	if info, err := os.Stat(basePath); !os.IsNotExist(err) {
		if info.IsDir() {
			return true, nil
		} else {
			return false, fmt.Errorf("data directory exists but is not a directory")
		}
	}
	return false, nil
}

func CreateDataDir(basePath string) error {
	err := os.MkdirAll(basePath, 0755)
	if err != nil {
		return fmt.Errorf("failed to make data directory structure: %v", err)
	}
	return nil
}
