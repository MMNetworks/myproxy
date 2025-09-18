package logging

import (
	"fmt"
	"myproxy/readconfig"
	"time"
)

type AccessLogRecord struct {
	// proxy hostname
	Proxy string
	// upstream proxy IP
	ProxyIP string
	// session ID
	SessionID int64
	// source IP
	SourceIP string
	// destinaion IP
	DestinationIP string
	// User Agent
	UserAgent string
	// forwarded IP from header
	ForwardedIP string
	// upstream proxy IP
	UpstreamProxyIP string
	// HTTP method used
	Method string
	// HTTP scheme
	Scheme string
	// HTTP URL requested
	Url string
	// HTTP protocol version requested
	Version string
	// HTTP response code
	Status string
	// bytes in
	BytesIN int64
	// bytes out
	BytesOUT int64
	// tunneled protocol
	Protocol string
	// connection start time
	Starttime time.Time
	// connection end time
	Endtime time.Time
	// connection duration
	Duration time.Duration
	// connection duration
	VirusList string
}

func humanReadableBitrate(bps float64) string {
	const (
		Kbps = 1_000
		Mbps = 1_000_000
		Gbps = 1_000_000_000
		Tbps = 1_000_000_000_000
	)

	switch {
	case bps >= Tbps:
		return fmt.Sprintf("%.2fTbps", bps/Tbps)
	case bps >= Gbps:
		return fmt.Sprintf("%.2fGbps", bps/Gbps)
	case bps >= Mbps:
		return fmt.Sprintf("%.2fMbps", bps/Mbps)
	case bps >= Kbps:
		return fmt.Sprintf("%.2fKbps", bps/Kbps)
	default:
		return fmt.Sprintf("%.2fbps", bps)
	}
}

func AccesslogWrite(record AccessLogRecord) (int, error) {
	var accesslogFilename string = "STDOUT"
	if readconfig.Config != nil {
		accesslogFilename = readconfig.Config.Logging.AccessLog
	}
	recordMbIN := humanReadableBitrate(float64(record.BytesIN) / float64(record.Duration.Seconds()))
	recordMbOUT := humanReadableBitrate(float64(record.BytesOUT) / float64(record.Duration.Seconds()))

	accessLogline := fmt.Sprintf("proxy=%s|proxyIP=%s|sessionID=%d|sourceIP=%s|destinationIP=%s|user-agent=%s|forwardedIP=%s|upstreamProxyIP=%s|method=%s|scheme=%s|url=%s|version=%s|status=%s|virus=%s|bytesIN=%d|bytesOUT=%d|protocol=%s|starttime=%s|endtime=%s|duration=%s|speedIN=%s|speedOUT=%s\n", record.Proxy, record.ProxyIP, record.SessionID, record.SourceIP, record.DestinationIP, record.UserAgent, record.ForwardedIP, record.UpstreamProxyIP, record.Method, record.Scheme, record.Url, record.Version, record.Status, record.VirusList, record.BytesIN, record.BytesOUT, record.Protocol, record.Starttime.Format(time.RFC1123), record.Endtime.Format(time.RFC1123), record.Duration.String(), recordMbIN, recordMbOUT)

	length, err := osPrintf(accesslogFilename, "ACCESS", accessLogline)

	return length, err
}

func AccesslogWriteStart(record AccessLogRecord) (int, error) {
	var accesslogFilename string = "STDOUT"
	if readconfig.Config != nil {
		accesslogFilename = readconfig.Config.Logging.AccessLog
	}
	recordMbIN := humanReadableBitrate(float64(record.BytesIN) / float64(record.Duration.Seconds()))
	recordMbOUT := humanReadableBitrate(float64(record.BytesOUT) / float64(record.Duration.Seconds()))

	accessLogline := fmt.Sprintf("proxy=%s|proxyIP=%s|sessionID=%d|sourceIP=%s|destinationIP=%s|user-agent=%s|forwardedIP=%s|upstreamProxyIP=%s|method=%s|scheme=%s|url=%s|version=%s|status=%s|virus=%s|bytesIN=%d|bytesOUT=%d|protocol=%s|starttime=%s|endtime=%s|duration=%s|speedIN=%s|speedOUT=%s\n", record.Proxy, record.ProxyIP, record.SessionID, record.SourceIP, record.DestinationIP, record.UserAgent, record.ForwardedIP, record.UpstreamProxyIP, record.Method, record.Scheme, record.Url, record.Version, record.Status, record.VirusList, record.BytesIN, record.BytesOUT, record.Protocol, record.Starttime.Format(time.RFC1123), record.Endtime.Format(time.RFC1123), record.Duration.String(), recordMbIN, recordMbOUT)

	length, err := osPrintf(accesslogFilename, "STARTLOG", accessLogline)

	return length, err
}
