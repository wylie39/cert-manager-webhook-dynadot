package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DynadotClient represents a client for the Dynadot API
type DynadotClient struct {
	ApiKey string
	SecretKey string
	BaseURL   string
	HTTPClient *http.Client
}

// MainDNSRecord represents a main DNS record
type MainDNSRecord struct {
	RecordType   string `json:"record_type"`
	RecordValue1 string `json:"record_value1"`
	RecordValue2 string `json:"record_value2,omitempty"`
}

// SubDNSRecord represents a sub DNS record
type SubDNSRecord struct {
	SubHost      string `json:"sub_host,omitempty"`
	RecordType   string `json:"record_type,omitempty"`
	RecordValue1 string `json:"record_value1,omitempty"`
	RecordValue2 string `json:"record_value2,omitempty"`
}

// SetDNSRequest represents the request body for SET_DNS command
type SetDNSRequest struct {
	DNSMainList              []MainDNSRecord `json:"dns_main_list"`
	SubList                  []SubDNSRecord  `json:"sub_list,omitempty"`
	TTL                      int64           `json:"ttl,omitempty"`
	AddDNSToCurrentSetting   bool            `json:"add_dns_to_current_setting,omitempty"`
}

// SetDNSResponse represents the API response for SET_DNS command
type SetDNSResponse struct {
	Code    string    `json:"code"`
	Message string `json:"message"`
}


// DNSResponse represents the API response for DNS operations
type DNSResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    any `json:"data,omitempty"`
}

// NewDynadotClient creates a new Dynadot API client
func NewDynadotClient(secretKey string, apiKey string) *DynadotClient {
	return &DynadotClient{
		ApiKey: apiKey,
		SecretKey: secretKey,
		BaseURL:   "https://api.dynadot.com/restful",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// generateSignature creates HMAC-SHA256 signature for the request
func (c *DynadotClient) generateSignature(fullPathAndQuery, xRequestID, requestBody string) string {
	// Create the string to sign
	stringToSign := c.ApiKey + "\n" + fullPathAndQuery + "\n" + xRequestID + "\n" + requestBody
	
	// Create HMAC-SHA256 hash
	h := hmac.New(sha256.New, []byte(c.SecretKey))
	h.Write([]byte(stringToSign))
	signature := hex.EncodeToString(h.Sum(nil))
	
	return signature
}

// makeRequest performs the actual HTTP request with proper headers and signature
func (c *DynadotClient) makeRequest(method, endpoint string, requestBody interface{}) (*http.Response, error) {
	var bodyBytes []byte
	var err error
	
	// Marshal request body if provided
	if requestBody != nil {
		bodyBytes, err = json.Marshal(requestBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}
	
	// Create request
	url := c.BaseURL + endpoint
	req, err := http.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)
	
	// Generate X-Request-Id (you might want to use a UUID library for this)
	xRequestID := fmt.Sprintf("req_%d", time.Now().UnixNano())
	req.Header.Set("X-Request-Id", xRequestID)
	
	// Generate signature
	bodyString := ""
	if bodyBytes != nil {
		bodyString = string(bodyBytes)
	}
	signature := c.generateSignature(endpoint, xRequestID, bodyString)
	req.Header.Set("X-Signature", signature)
	
	// Make the request
	return c.HTTPClient.Do(req)
}

// GetDNSRecords retrieves DNS records for a domain
func (c *DynadotClient) GetDNSRecords(domain string) (*DNSResponse, error) {
	endpoint := fmt.Sprintf("/v1/domains/%s/records", domain)
	
	resp, err := c.makeRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var dnsResponse DNSResponse
	if err := json.Unmarshal(body, &dnsResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &dnsResponse, nil
}

// SetDNSRecords sets DNS records for a domain using the SET_DNS command
func (c *DynadotClient) SetDNSRecords(domain string, request SetDNSRequest) (*SetDNSResponse, error) {
	endpoint := fmt.Sprintf("/v1/domains/%s/records", domain)
	
	resp, err := c.makeRequest("POST", endpoint, request)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	println(string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var setDNSResponse SetDNSResponse
	if err := json.Unmarshal(body, &setDNSResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &setDNSResponse, nil
}



