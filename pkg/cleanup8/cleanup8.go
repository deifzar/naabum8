package cleanup8

import (
	"os"
	"path/filepath"
	"time"

	"deifzar/naabum8/pkg/log8"
)

type Cleanup8 struct{}

func NewCleanup8() Cleanup8Interface {
	return &Cleanup8{}
}

func (c *Cleanup8) CleanupDirectory(directory string, maxAge time.Duration) error {
	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log8.BaseLogger.Error().Err(err).Str("path", path).Msg("Error accessing file during cleanup")
			return err
		}

		// Skip the directory itself
		if info.IsDir() {
			return nil
		}

		// Check if file is older than maxAge
		if time.Since(info.ModTime()) > maxAge {
			log8.BaseLogger.Info().Str("file", path).Str("age", time.Since(info.ModTime()).String()).Msg("Removing old file")
			if err := os.Remove(path); err != nil {
				log8.BaseLogger.Error().Err(err).Str("file", path).Msg("Failed to remove old file")
				return err
			}
			log8.BaseLogger.Debug().Str("file", path).Msg("Successfully removed old file")
		}
		return nil
	})
}
