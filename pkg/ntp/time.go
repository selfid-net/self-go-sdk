package ntp

import (
	"sync/atomic"
	"time"

	"github.com/beevik/ntp"
)

var (
	TimeFunc  = NewTime().Now
	NtpServer = "time.google.com"
)

// Time contains information about the NTP server
type Time struct {
	lastCheck int64
	ntpOffset int64
}

func NewTime() *Time {
	t := Time{}
	t.syncNTP()
	return &t
}

func (c *Time) Now() time.Time {
	now := time.Now().Add(c.timeOffset())

	if now.After(c.lastChecked().Add(1 * time.Hour)) {
		c.syncNTP()
		now = time.Now().Add(c.timeOffset())
	}

	return now
}

func (c *Time) timeOffset() time.Duration {
	return time.Duration(atomic.LoadInt64(&c.ntpOffset))
}

func (c *Time) lastChecked() time.Time {
	return time.Unix(atomic.LoadInt64(&c.lastCheck), 0)
}

func (c *Time) syncNTP() error {
	response, err := ntp.Query(NtpServer)
	if err != nil {
		return err
	}

	atomic.StoreInt64(&c.ntpOffset, int64(response.ClockOffset))
	atomic.StoreInt64(&c.lastCheck, time.Now().Add(c.timeOffset()).Unix())

	return nil
}

// Before returns true if a given time is before the current time
func Before(t time.Time) bool {
	return t.After(TimeFunc().Add(time.Second*5))
}

// After returns true if a given time is after the current time
func After(t time.Time) bool {
	return TimeFunc().After(t)
}
