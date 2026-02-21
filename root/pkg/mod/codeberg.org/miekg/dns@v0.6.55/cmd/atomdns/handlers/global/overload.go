package global

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

func overload(ctx context.Context, addr string) {
	client := http.Client{Timeout: 3 * time.Second}

	ticker := time.NewTicker(2 * time.Second)
	url := "http://" + addr + "/health"

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				HealthDuration.Observe(time.Since(start).Seconds())
				HealthFailures.Inc()
				log.Error("Failed health", Err(err))
				continue
			}
			resp.Body.Close()
			elapsed := time.Since(start)
			HealthDuration.Observe(elapsed.Seconds())
			if elapsed > time.Second { // 1s is pretty random, but a *local* scrape taking that long isn't good
				log.Warn("Slow health", slog.Duration("elapsed", elapsed))
			}

		case <-ctx.Done():
			return
		}
	}
}
