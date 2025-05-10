package model8

// "io"
// "path/filepath"
// "bufio"

type Scan8 struct {
	Hostnames []string `form:"hostnames" json:"hostnames" binding:"dive,hostname_rfc1123"` // http_url fails if the target are hostnames
}

func (s *Scan8) AddHostname(h string) []string {
	s.Hostnames = append(s.Hostnames, h)
	return s.Hostnames
}
