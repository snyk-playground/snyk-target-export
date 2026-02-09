package internal

import (
	"net/http"
	"testing"
	"time"
)

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{408, 429, 500, 502, 503, 504, 530}
	for _, code := range retryable {
		if !isRetryableStatus(code) {
			t.Errorf("isRetryableStatus(%d) = false, want true", code)
		}
	}

	notRetryable := []int{200, 201, 204, 301, 400, 401, 403, 404, 409, 422}
	for _, code := range notRetryable {
		if isRetryableStatus(code) {
			t.Errorf("isRetryableStatus(%d) = true, want false", code)
		}
	}
}

func TestGetRetryAfter(t *testing.T) {
	// Nil response
	if d := getRetryAfter(nil); d != 0 {
		t.Errorf("getRetryAfter(nil) = %v, want 0", d)
	}

	// No header
	resp := &http.Response{Header: http.Header{}}
	if d := getRetryAfter(resp); d != 0 {
		t.Errorf("getRetryAfter(no header) = %v, want 0", d)
	}

	// Valid integer header
	resp.Header.Set("Retry-After", "5")
	if d := getRetryAfter(resp); d != 5*time.Second {
		t.Errorf("getRetryAfter(5) = %v, want 5s", d)
	}

	// Non-integer header (e.g. HTTP date) returns 0
	resp.Header.Set("Retry-After", "Thu, 01 Jan 2026 00:00:00 GMT")
	if d := getRetryAfter(resp); d != 0 {
		t.Errorf("getRetryAfter(date) = %v, want 0", d)
	}
}

func TestCalculateBackoff(t *testing.T) {
	cfg := RetryConfig{
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
	}

	// attempt 0 -> 1s
	if d := calculateBackoff(0, cfg); d != 1*time.Second {
		t.Errorf("attempt 0: got %v, want 1s", d)
	}

	// attempt 1 -> 2s
	if d := calculateBackoff(1, cfg); d != 2*time.Second {
		t.Errorf("attempt 1: got %v, want 2s", d)
	}

	// attempt 2 -> 4s
	if d := calculateBackoff(2, cfg); d != 4*time.Second {
		t.Errorf("attempt 2: got %v, want 4s", d)
	}

	// attempt 5 -> 32s, capped to 30s
	if d := calculateBackoff(5, cfg); d != 30*time.Second {
		t.Errorf("attempt 5: got %v, want 30s (capped)", d)
	}
}
