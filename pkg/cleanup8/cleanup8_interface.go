package cleanup8

import (
	"time"
)

type Cleanup8Interface interface {
	CleanupDirectory(directory string, maxAge time.Duration) error
}
