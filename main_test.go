package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollmentHeartbeatListAndRevocation(t *testing.T) {
	server := newServer("01234567890123456789012345678901")
	handler := server.routes()
	enrollBody := []byte(`{"model":"Pixel","osVersion":"Android 15","appVersion":"1.2.0"}`)
	enroll := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(enrollBody))
	enrollResponse := httptest.NewRecorder()
	handler.ServeHTTP(enrollResponse, enroll)
	if enrollResponse.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want %d: %s", enrollResponse.Code, http.StatusCreated, enrollResponse.Body)
	}
	var enrolled struct {
		Device      Device `json:"device"`
		DeviceToken string `json:"deviceToken"`
	}
	if err := json.Unmarshal(enrollResponse.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	if enrolled.Device.ID == "" || enrolled.DeviceToken == "" {
		t.Fatal("enrollment did not return device ID and credential")
	}

	heartbeat := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewBufferString(`{"appVersion":"1.2.1","osVersion":"Android 15","batteryPercent":73}`))
	heartbeat.Header.Set("X-Device-ID", enrolled.Device.ID)
	heartbeat.Header.Set("Authorization", "Bearer "+enrolled.DeviceToken)
	heartbeatResponse := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatResponse, heartbeat)
	if heartbeatResponse.Code != http.StatusNoContent {
		t.Fatalf("heartbeat status = %d, want %d", heartbeatResponse.Code, http.StatusNoContent)
	}

	list := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	list.Header.Set("Authorization", "Bearer "+server.adminToken)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResponse.Code, http.StatusOK)
	}
	var result struct { Devices []Device `json:"devices"` }
	if err := json.Unmarshal(listResponse.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 1 || result.Devices[0].BatteryPercent != 73 || result.Devices[0].AppVersion != "1.2.1" {
		t.Fatalf("unexpected device record: %+v", result.Devices)
	}

	revoke := httptest.NewRequest(http.MethodDelete, "/v1/devices/"+enrolled.Device.ID, nil)
	revoke.Header.Set("Authorization", "Bearer "+server.adminToken)
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", revokeResponse.Code, http.StatusNoContent)
	}

	heartbeatResponse = httptest.NewRecorder()
	handler.ServeHTTP(heartbeatResponse, heartbeat)
	if heartbeatResponse.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat after revocation status = %d, want %d", heartbeatResponse.Code, http.StatusUnauthorized)
	}
}

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"model":"Pixel"} {"model":"Other"}`))
	response := httptest.NewRecorder()
	var target enrollRequest
	if decodeJSON(response, request, &target) == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}