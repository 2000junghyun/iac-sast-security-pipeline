package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// ValidateMethod는 HTTP 메서드를 검증
func ValidateMethod(r *http.Request, allowedMethods ...string) error {
	for _, method := range allowedMethods {
		if r.Method == method {
			return nil
		}
	}
	return fmt.Errorf("method not allowed")
}

// ValidateAPISecret는 API Secret을 검증
func ValidateAPISecret(r *http.Request, expectedSecret string) error {
	receivedSecret := r.Header.Get("X-API-Secret")
	if receivedSecret != expectedSecret {
		log.Printf("Invalid API secret received")
		return fmt.Errorf("unauthorized")
	}
	return nil
}

// ParseJSONRequest는 JSON 요청을 파싱
func ParseJSONRequest(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		log.Printf("Failed to parse JSON: %v", err)
		return fmt.Errorf("invalid JSON payload")
	}
	return nil
}
