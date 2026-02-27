package httpapi

import (
	"context"
	"strings"
	"time"
)

// LicenseVerifyURL is the endpoint of your central billing/licensing server.
// For now, we point it to a dummy endpoint, but you will change this to your actual server.
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
	// For testing, any key starting with "VPS-LIFETIME-" is valid forever.
	// Any key starting with "VPS-MONTHLY-" is valid for 30 days.
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

	// --- REAL PRODUCTION MODE (Uncomment when your billing server is ready) ---
	/*
		payload, _ := json.Marshal(map[string]string{
			"license_key": key,
			"server_ip": ip, // <--- Here you send the IP to your server!
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, LicenseVerifyURL, bytes.NewReader(payload))
		if err != nil {
			return LicenseStatus{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return LicenseStatus{Valid: true, Status: "active", Message: "License server unreachable. Grace period active."}, nil
		}
		defer resp.Body.Close()

		var status LicenseStatus
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return LicenseStatus{}, err
		}
		
		// If status.Valid is true, your central server has verified that
		// this license key is locked to this specific server IP.
		return status, nil
	*/

	return LicenseStatus{Valid: false, Status: "invalid", Message: "Invalid license key format."}, nil
}
	if strings.HasPrefix(key, "VPS-MONTHLY-") {
		return LicenseStatus{Valid: true, Status: "active", ExpiryDate: time.Now().AddDate(0, 1, 0).Format(time.RFC3339), Message: "Monthly License Active"}, nil
	}
	if key == "VPS-EXPIRED" {
		return LicenseStatus{Valid: false, Status: "expired", Message: "Your license has expired. Please renew."}, nil
	}
	if key == "VPS-BANNED" {
		return LicenseStatus{Valid: false, Status: "suspended", Message: "This license has been suspended for terms violation."}, nil
	}

	return LicenseStatus{Valid: false, Status: "invalid", Message: "Invalid license key format."}, nil
}
