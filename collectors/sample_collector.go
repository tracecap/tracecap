package collectors

import (
	"github.com/tracecap/tracecap/tracecappb"
)

type PendingSample struct {
	PID, TID int
	Sample   *tracecappb.ThreadSample
}

type SampleStats struct {
	Dropped uint64
}

type SampleCollector interface {
	Start(chan PendingSample) error
	Stop() error
	Close()
	Stats() SampleStats
}

type MultipleSampleCollector struct {
	collectors []SampleCollector
}

func NewMultipleSampleCollector(collectors []SampleCollector) *MultipleSampleCollector {
	multi := &MultipleSampleCollector{
		collectors: collectors,
	}

	return multi
}

func (mc *MultipleSampleCollector) Start(out chan PendingSample) error {
	for _, c := range mc.collectors {
		err := c.Start(out)
		if err != nil {
			return err
		}
	}

	return nil
}

func (mc *MultipleSampleCollector) Stop() error {
	for _, c := range mc.collectors {
		err := c.Stop()
		if err != nil {
			return err
		}
	}

	return nil
}

func (mc *MultipleSampleCollector) Close() {
	mc.Stop()

	for _, c := range mc.collectors {
		c.Close()
	}
}

func (mc *MultipleSampleCollector) Stats() SampleStats {
	stats := SampleStats{}

	for _, c := range mc.collectors {
		stat := c.Stats()
		stats.Dropped += stat.Dropped
	}

	return stats
}
