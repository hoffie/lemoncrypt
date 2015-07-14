package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// MetricCollector can be used to collect statistics and write them to a
// CSV file.
type MetricCollector struct {
	outfd   *os.File
	counter uint64
}

// MetricRecord represents a single metric entry.
type MetricRecord struct {
	collector  *MetricCollector
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	OrigSize   uint32
	ResultSize uint32
	Success    bool
}

// NewMetricCollector returns a new MetricCollector instance.
// It requires the given outfile not to exist before this call and will
// create it.
func NewMetricCollector(outfile string) (*MetricCollector, error) {
	mc := &MetricCollector{}
	// not race-condition-safe, but it's just an attempt to
	// avoid overwriting previously collected data.
	_, err := os.Stat(outfile)
	if !os.IsNotExist(err) {
		return nil, errors.New("metrics output file already exists")
	}
	mc.outfd, err = os.Create(outfile)
	if err != nil {
		return nil, fmt.Errorf("unable to open metrics output file for writing: %s", err)
	}
	err = mc.writeHeader()
	return mc, nil
}

// writeHeader outputs a CSV header to the output file.
func (mc *MetricCollector) writeHeader() error {
	_, err := mc.outfd.WriteString("StartTime;EndTime;Duration (ns);OrigSize (B);ResultSize (B);Success\n")
	if err != nil {
		return fmt.Errorf("failed to write header: %s", err)
	}
	return nil
}

// NewRecord returns a new MetricRecord instance which is initialized with
// the current time as the StartTime and is associated with this
// MetricCollector instance, so that later calls to .Commit know where to
// write.
func (mc *MetricCollector) NewRecord() *MetricRecord {
	r := &MetricRecord{}
	r.StartTime = time.Now()
	r.collector = mc
	return r
}

// Commit updates the EndTime field and passes this record to the collector
// so it can be serialized to disk.
func (mr *MetricRecord) Commit() error {
	mr.EndTime = time.Now()
	mr.Duration = mr.EndTime.Sub(mr.StartTime)
	return mr.collector.writeRecord(mr)
}

// writeRecord formats the given entry and writes it to the output file.
// A file sync is triggered every 128 seconds in order to reduce the risk
// for information loss in case of crashes.
func (mc *MetricCollector) writeRecord(r *MetricRecord) error {
	if mc == nil {
		// if we attempt to write to an uninitialized MetricCollector, we fail
		// silently as this means that none has been configured.
		return nil
	}
	_, err := fmt.Fprintf(mc.outfd, "%s;%s;%d;%d;%d;%t\n",
		r.StartTime, r.EndTime, r.Duration, r.OrigSize, r.ResultSize, r.Success)
	if err != nil {
		return fmt.Errorf("failed to write record: %s", err)
	}
	mc.counter++
	if mc.counter%128 == 0 {
		err = mc.outfd.Sync()
		if err != nil {
			return fmt.Errorf("failed to sync to disk: %s", err)
		}
	}
	return nil
}

// Close closes the underlying file handle.
func (mc *MetricCollector) Close() error {
	return mc.outfd.Close()
}
