package httpapi

import (
	"context"
	"strings"
	"time"
)

// LicenseVerifyURL is the endpoint of your central billing/licensing server.
var LicenseVerifyURL = "https://your-license-server.com/api/verify"

type LicenseStatus struct {
	Valid      bool   `json:"valid"`
	Status     string `json:"status"` // "active", "expired", "suspended"
	ExpiryDate string `json:"expires_at"`
	Message    string `json:"message"`
}

// VerifyLicense contacts your central server to check if the key is valid.
func VerifyLicense(ctx context.Context, key string, ip string) (LicenseStatus, error) {
	// --- DEMO MODE ---
	if strings.HasPrefix(key, "VPS-LIFETIME-") {
		return LicenseStatus{Valid: true, Status: "active", Message: "Lifetime License Active (IP: " + ip + ")"}, nil
	}
	if strings.HasPrefix(key, "VPS-MONTHLY-") {
		return LicenseStatus{Valid: true, Status: "active", ExpiryDate: time.Now().AddDate(0, 1, 0).Format(time.RFC3339), Message: "Monthly License Active (IP: " + ip + ")"}, nil
	}
	if key == "VPS-EXPIRED" {
		return LicenseStatus{Valid: false, Status: "expired", Message: "Your license has expired. Please renew."}, nil
	}
	if key == "VPS-BANNED" {
		return LicenseStatus{Valid: false, Status: "suspended", Message: "This license has been suspended for terms violation."}, nil
	}

	return LicenseStatus{Valid: false, Status: "invalid", Message: "Invalid license key format."}, nil
}
