package logging

import (
	"myproxy/readconfig"
	"time"
)

type AccessLogRecord struct {
        // proxy hostname
        Proxy string
        // session ID
        SessionID int64
        // session state
        State string
        // source IP
        SourceIP string
        // destinaion IP
        DestinationIP string
        // forwarded IP from header
        ForwardedIP string
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
}

func AccesslogWrite (record AccessLogRecord) (int, error){
	var accesslogFilename string = "STDOUT"
        if readconfig.Config != nil {
               accesslogFilename = readconfig.Config.Logging.AccessLog
	}
	length, err := osPrintf(accesslogFilename,"ACCESS","proxy=%s,sessionID=%d,state=%s,sourceIP=%s,destinationIP=%s,forwardedIP=%s,method=%s,scheme=%s,url=%s,version=%s,status=%s,bytesIN=%d,bytesOUT=%d,protocol=%s,starttime=%s,endtime=%s,duaration=%s\n",record.Proxy,record.SessionID,record.State,record.SourceIP,record.DestinationIP,record.ForwardedIP,record.Method,record.Scheme,record.Url,record.Version,record.Status,record.BytesIN,record.BytesOUT,record.Protocol,record.Starttime.Format(time.RFC1123),record.Endtime.Format(time.RFC1123),record.Duration.String())
	return length,err
}

