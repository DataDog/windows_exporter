// +build windows

package collector

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/shirou/gopsutil/net"
	"time"
	"syscall"
)

var (
	tcpStateMapping = map[string]string{
		"ESTABLISHED":  "established",
		"SYN_SENT":     "opening",
		"SYN_RECEIVED": "opening",
		"FIN_WAIT1":    "closing",
		"FIN_WAIT2":    "closing",
		"TIME_WAIT":    "time_wait",
		"CLOSED":       "closing",
		"CLOSE_WAIT":   "closing",
		"LAST_ACK":     "closing",
		"LISTEN":       "listening",
		"CLOSING":      "closing",
		"DELETE":       "closing",
	}

	familyMapping = map[uint32]string{
		syscall.AF_INET: "ipv4",
		syscall.AF_INET6: "ipv6",
	}
)

func init() {
	registerCollector("tcp_local", NewTCPLocalCollector)
}

// A TCPLocalCollector is a Prometheus collector for GetExtendedTcpTable syscall through gopsutil
type TCPLocalCollector struct {
	Connections     *prometheus.Desc
}

// NewTCPCollector ...
func NewTCPLocalCollector() (Collector, error) {
	const subsystem = "tcp"

	return &TCPLocalCollector{
		Connections: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "connections"),
			"Number of TCP Connections per state",
			[]string{"af", "state"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *TCPLocalCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ctx, ch); err != nil {
		log.Error("failed collecting tcp metrics:", desc, err)
		return err
	}
	return nil
}

func (c *TCPLocalCollector) collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	syscallCtx, syscallCancel := context.WithTimeout(context.Background(), time.Second)
	defer syscallCancel()

	connections, err := net.ConnectionsWithContext(syscallCtx, "tcp")
	if err != nil {
		return c.Connections, err
	}

	tcp4Counts := make(map[string]float64)
	tcp6Counts := make(map[string]float64)

	for _, con := range connections {
		var counts = tcp4Counts
		if con.Family == syscall.AF_INET6 {
			counts = tcp6Counts
		}

		if status, found := tcpStateMapping[con.Status]; found {
			counts[status] += 1
		}
	}

	for status, value := range tcp4Counts {
		ch <- prometheus.MustNewConstMetric(c.Connections, prometheus.GaugeValue, value, "ipv4", status)
	}

	for status, value := range tcp6Counts {
		ch <- prometheus.MustNewConstMetric(c.Connections, prometheus.GaugeValue, value, "ipv6", status)
	}

	return c.Connections, nil
}
