package sign

import (
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	now := time.Now()
	testcases := []struct {
		expire time.Time
		days   int
	}{
		{now.Add(5 * Day), 5},
		{now.Add(-9 * Day), -9},
	}
	for i, tc := range testcases {
		days := Expired(now, tc.expire)
		if days != tc.days {
			t.Errorf("test %d, expected %d, got %d", i, tc.days, days)
		}
	}
}
