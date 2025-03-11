package models

import (
    "encoding/json"
    "testing"
    "time"

    jwt "github.com/golang-jwt/jwt/v4"
)

// TestUserNameInCharSet tests the NameInCharSet method for various usernames
func TestUserNameInCharSet(t *testing.T) {
    tests := []struct {
        name     string
        username string
        expected bool
    }{
        {"empty", "", true},
        {"valid lowercase", "john.doe", true},
        {"valid uppercase", "JOHN-DOE", true},
        {"valid mixed", "John123", true},
        {"invalid char", "john_doe", false},
        {"invalid symbol", "john!doe", false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            // Assuming User struct is defined with field UserName in models package
            user := &User{UserName: tc.username}
            result := user.NameInCharSet()
            if result != tc.expected {
                t.Errorf("NameInCharSet() for username %q returned %v; expected %v", tc.username, result, tc.expected)
            }
        })
    }
}

// TestJWTClaimsToken tests creation, signing, and parsing of JWT claims
func TestJWTClaimsToken(t *testing.T) {
    signingKey := []byte("secret")
    expirationTime := time.Now().Add(1 * time.Hour)
    claims := &Claims{
        ID:         "user123",
        MacAddress: "00:11:22:33:44:55",
        Network:    "testnet",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(signingKey)
    if err != nil {
        t.Fatalf("Error signing token: %v", err)
    }

    parsedToken, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return signingKey, nil
    })
    if err != nil {
        t.Fatalf("Error parsing token: %v", err)
    }

    parsedClaims, ok := parsedToken.Claims.(*Claims)
    if !ok {
        t.Fatalf("Could not convert parsed claims")
    }
    if parsedClaims.ID != claims.ID || parsedClaims.MacAddress != claims.MacAddress || parsedClaims.Network != claims.Network {
        t.Errorf("Parsed claims do not match original claims")
    }
}

// TestJSONMarshallingSignInResDto tests the JSON marshalling/unmarshalling of SignInResDto
func TestJSONMarshallingSignInResDto(t *testing.T) {
    original := SignInResDto{
        Status: "success",
        User: User{
            UserName: "testuser",
        },
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling SignInResDto: %v", err)
    }
    var decoded SignInResDto
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling SignInResDto: %v", err)
    }
    if decoded.Status != original.Status || decoded.User.UserName != original.User.UserName {
        t.Errorf("Decoded SignInResDto does not match original")
    }
}

// TestJSONMarshallingLicenseLimits tests the JSON marshalling/unmarshalling of LicenseLimits
func TestJSONMarshallingLicenseLimits(t *testing.T) {
    original := LicenseLimits{
        Servers:  3,
        Users:    10,
        Hosts:    5,
        Clients:  7,
        Networks: 2,
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling LicenseLimits: %v", err)
    }
    var decoded LicenseLimits
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling LicenseLimits: %v", err)
    }
    if decoded.Servers != original.Servers || decoded.Users != original.Users || decoded.Hosts != original.Hosts ||
        decoded.Clients != original.Clients || decoded.Networks != original.Networks {
        t.Errorf("Decoded LicenseLimits does not match original")
    }
}
// TestJSONMarshallingGlobalConfig tests marshalling/unmarshalling of GlobalConfig
func TestJSONMarshallingGlobalConfig(t *testing.T) {
    original := GlobalConfig{Name: "GlobalTest"}
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling GlobalConfig: %v", err)
    }
    var decoded GlobalConfig
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling GlobalConfig: %v", err)
    }
    if decoded.Name != original.Name {
        t.Errorf("Decoded GlobalConfig does not match original; got %v, want %v", decoded.Name, original.Name)
    }
}

// TestJSONMarshallingAuthParams tests marshalling/unmarshalling of AuthParams
func TestJSONMarshallingAuthParams(t *testing.T) {
    original := AuthParams{
        MacAddress: "AA:BB:CC:DD:EE:FF",
        ID:         "auth123",
        Password:   "passw0rd",
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling AuthParams: %v", err)
    }
    var decoded AuthParams
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling AuthParams: %v", err)
    }
    if decoded.MacAddress != original.MacAddress || decoded.ID != original.ID || decoded.Password != original.Password {
        t.Errorf("Decoded AuthParams does not match original")
    }
}

// TestJSONMarshallingSuccessResponse tests marshalling/unmarshalling of SuccessResponse which uses an interface{} field
func TestJSONMarshallingSuccessResponse(t *testing.T) {
    original := SuccessResponse{
        Code:    200,
        Message: "OK",
        Response: map[string]string{
            "key": "value",
        },
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling SuccessResponse: %v", err)
    }
    var decoded SuccessResponse
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling SuccessResponse: %v", err)
    }
    if decoded.Code != original.Code || decoded.Message != original.Message {
        t.Errorf("Decoded SuccessResponse does not match original")
    }
}

// TestJSONMarshallingCheckInResponse tests marshalling/unmarshalling of CheckInResponse
func TestJSONMarshallingCheckInResponse(t *testing.T) {
    original := CheckInResponse{
        Success:          true,
        NeedPeerUpdate:   false,
        NeedConfigUpdate: true,
        NeedKeyUpdate:    false,
        NeedDelete:       false,
        NodeMessage:      "Node updated successfully",
        IsPending:        false,
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling CheckInResponse: %v", err)
    }
    var decoded CheckInResponse
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling CheckInResponse: %v", err)
    }
    if decoded.Success != original.Success || decoded.NeedPeerUpdate != original.NeedPeerUpdate ||
        decoded.NeedConfigUpdate != original.NeedConfigUpdate || decoded.NeedKeyUpdate != original.NeedKeyUpdate ||
        decoded.NeedDelete != original.NeedDelete || decoded.NodeMessage != original.NodeMessage ||
        decoded.IsPending != original.IsPending {
        t.Errorf("Decoded CheckInResponse does not match original")
    }
}

// TestJSONMarshallingServerConfig tests marshalling/unmarshalling of ServerConfig
func TestJSONMarshallingServerConfig(t *testing.T) {
    original := ServerConfig{
        CoreDNSAddr:       "8.8.8.8",
        API:               "http://localhost/api",
        APIPort:           "8080",
        DNSMode:           "default",
        Version:           "1.0.0",
        MQPort:            "1883",
        MQUserName:        "user",
        MQPassword:        "password",
        BrokerType:        "mqtt",
        Server:            "server1",
        Broker:            "broker1",
        IsPro:             true,
        TrafficKey:        []byte("trafficKey"),
        MetricInterval:    "60s",
        MetricsPort:       9090,
        ManageDNS:         true,
        Stun:              true,
        StunServers:       "stun:stun.l.google.com:19302",
        EndpointDetection: true,
        DefaultDomain:     "example.com",
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling ServerConfig: %v", err)
    }
    var decoded ServerConfig
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling ServerConfig: %v", err)
    }
    if decoded.API != original.API || decoded.CoreDNSAddr != original.CoreDNSAddr || decoded.APIPort != original.APIPort {
        t.Errorf("Decoded ServerConfig does not match original for key fields")
    }
}

// TestJSONMarshallingSsoLoginResDto tests marshalling/unmarshalling of SsoLoginResDto
func TestJSONMarshallingSsoLoginResDto(t *testing.T) {
    original := SsoLoginResDto{
        User:      "ssoUser",
        AuthToken: "ssoToken",
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling SsoLoginResDto: %v", err)
    }
    var decoded SsoLoginResDto
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling SsoLoginResDto: %v", err)
    }
    if decoded.User != original.User || decoded.AuthToken != original.AuthToken {
        t.Errorf("Decoded SsoLoginResDto does not match original")
    }
}
// TestExpiredJWTClaimsToken tests parsing of an expired JWT token and expects failure
func TestExpiredJWTClaimsToken(t *testing.T) {
    signingKey := []byte("secret")
    expirationTime := time.Now().Add(-1 * time.Hour) // expired token
    claims := &Claims{
        ID:         "userExpired",
        MacAddress: "FF:EE:DD:CC:BB:AA",
        Network:    "expirednet",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(signingKey)
    if err != nil {
        t.Fatalf("Error signing token: %v", err)
    }
    // Parse token, expecting an error due to expiration
    _, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return signingKey, nil
    })
    if err == nil {
        t.Errorf("Expected token parsing to fail due to expiration, but it succeeded")
    }
}

// TestJSONMarshallingIngressGwUsers tests JSON marshalling and unmarshalling of IngressGwUsers
func TestJSONMarshallingIngressGwUsers(t *testing.T) {
    // Create an instance of IngressGwUsers; note that ReturnUser is assumed to be a defined type.
    original := IngressGwUsers{
        NodeID:  "node123",
        Network: "network1",
        Users:   []ReturnUser{{}}, // Using a default ReturnUser instance
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling IngressGwUsers: %v", err)
    }
    var decoded IngressGwUsers
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling IngressGwUsers: %v", err)
    }
    if decoded.NodeID != original.NodeID || decoded.Network != original.Network {
        t.Errorf("Decoded IngressGwUsers does not match original")
    }
}

// TestJSONMarshallingSsoLoginData tests the JSON marshalling and unmarshalling of SsoLoginData
func TestJSONMarshallingSsoLoginData(t *testing.T) {
    original := SsoLoginData{
        Expiration:    time.Now().Add(2 * time.Hour),
        OauthProvider: "provider",
        OauthCode:     "code123",
        Username:      "testuser",
        AmbAccessToken:"ambToken",
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling SsoLoginData: %v", err)
    }
    var decoded SsoLoginData
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling SsoLoginData: %v", err)
    }
    if decoded.OauthProvider != original.OauthProvider || decoded.OauthCode != original.OauthCode || decoded.Username != original.Username {
        t.Errorf("Decoded SsoLoginData does not match original")
    }
}

// TestJSONMarshallingGetClientConfReqDto tests the JSON marshalling and unmarshalling of GetClientConfReqDto
func TestJSONMarshallingGetClientConfReqDto(t *testing.T) {
    original := GetClientConfReqDto{PreferredIp: "192.168.1.1"}
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling GetClientConfReqDto: %v", err)
    }
    var decoded GetClientConfReqDto
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling GetClientConfReqDto: %v", err)
    }
    if decoded.PreferredIp != original.PreferredIp {
        t.Errorf("Decoded GetClientConfReqDto does not match original")
    }
}

// TestHookDetailsFunction tests that the Hook function in HookDetails is executed correctly
func TestHookDetailsFunction(t *testing.T) {
    called := false
    hd := HookDetails{
        Hook: func() error {
            called = true
            return nil
        },
        Interval: 5 * time.Second,
    }
    err := hd.Hook()
    if err != nil {
        t.Fatalf("Hook function returned error: %v", err)
    }
    if !called {
        t.Errorf("Hook function was not called as expected")
    }
}
// TestFormFieldsMarshalling validates JSON marshalling/unmarshalling for FormFields and SignInReqDto.
func TestFormFieldsMarshalling(t *testing.T) {
    original := SignInReqDto{
        FormFields: FormFields{
            {Id: "username", Value: "testuser"},
            {Id: "password", Value: "secret"},
        },
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling SignInReqDto: %v", err)
    }
    var decoded SignInReqDto
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling SignInReqDto: %v", err)
    }
    if len(decoded.FormFields) != len(original.FormFields) {
        t.Errorf("FormFields length mismatch: got %d, want %d", len(decoded.FormFields), len(original.FormFields))
    }
    for i, field := range original.FormFields {
        if decoded.FormFields[i].Id != field.Id || decoded.FormFields[i].Value != field.Value {
            t.Errorf("Decoded field %d does not match original: got %+v, want %+v", i, decoded.FormFields[i], field)
        }
    }
}

// TestRsrcURLInfoMarshalling validates JSON marshalling/unmarshalling for RsrcURLInfo.
func TestRsrcURLInfoMarshalling(t *testing.T) {
    original := RsrcURLInfo{
        Method: "GET",
        Path:   "/test/path",
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling RsrcURLInfo: %v", err)
    }
    var decoded RsrcURLInfo
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling RsrcURLInfo: %v", err)
    }
    if decoded.Method != original.Method || decoded.Path != original.Path {
        t.Errorf("Decoded RsrcURLInfo does not match original; got %+v, want %+v", decoded, original)
    }
}

// TestEgressGatewayRequestMarshalling validates JSON marshalling/unmarshalling for EgressGatewayRequest.
func TestEgressGatewayRequestMarshalling(t *testing.T) {
    original := EgressGatewayRequest{
        NodeID:     "node1",
        NetID:      "net1",
        NatEnabled: "true",
        Ranges:     []string{"192.168.0.0/24", "10.0.0.0/8"},
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling EgressGatewayRequest: %v", err)
    }
    var decoded EgressGatewayRequest
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling EgressGatewayRequest: %v", err)
    }
    if decoded.NodeID != original.NodeID || decoded.NetID != original.NetID || decoded.NatEnabled != original.NatEnabled {
        t.Errorf("Decoded EgressGatewayRequest does not match original; got %+v, want %+v", decoded, original)
    }
    if len(decoded.Ranges) != len(original.Ranges) {
        t.Errorf("Ranges length mismatch: got %d, want %d", len(decoded.Ranges), len(original.Ranges))
    }
    for i, r := range original.Ranges {
        if decoded.Ranges[i] != r {
            t.Errorf("Range at index %d does not match: got %s, want %s", i, decoded.Ranges[i], r)
        }
    }
}

// TestHostRelayRequestMarshalling validates JSON marshalling/unmarshalling for HostRelayRequest.
func TestHostRelayRequestMarshalling(t *testing.T) {
    original := HostRelayRequest{
        HostID:       "host1",
        RelayedHosts: []string{"host2", "host3"},
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling HostRelayRequest: %v", err)
    }
    var decoded HostRelayRequest
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling HostRelayRequest: %v", err)
    }
    if decoded.HostID != original.HostID {
        t.Errorf("Decoded HostID mismatch: got %s, want %s", decoded.HostID, original.HostID)
    }
    if len(decoded.RelayedHosts) != len(original.RelayedHosts) {
        t.Errorf("RelayedHosts length mismatch: got %d, want %d", len(decoded.RelayedHosts), len(original.RelayedHosts))
    }
    for i, host := range original.RelayedHosts {
        if decoded.RelayedHosts[i] != host {
            t.Errorf("RelayedHost at index %d: got %s, want %s", i, decoded.RelayedHosts[i], host)
        }
    }
}

// TestServerIDsMarshalling validates JSON marshalling/unmarshalling for ServerIDs.
func TestServerIDsMarshalling(t *testing.T) {
    original := ServerIDs{
        ServerIDs: []string{"s1", "s2", "s3"},
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling ServerIDs: %v", err)
    }
    var decoded ServerIDs
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling ServerIDs: %v", err)
    }
    if len(decoded.ServerIDs) != len(original.ServerIDs) {
        t.Errorf("ServerIDs length mismatch: got %d, want %d", len(decoded.ServerIDs), len(original.ServerIDs))
    }
    for i, id := range original.ServerIDs {
        if decoded.ServerIDs[i] != id {
            t.Errorf("ServerID at index %d: got %s, want %s", i, decoded.ServerIDs[i], id)
        }
    }
}

// TestTrafficKeysMarshalling validates JSON marshalling/unmarshalling for TrafficKeys.
func TestTrafficKeysMarshalling(t *testing.T) {
    original := TrafficKeys{
        Mine:   []byte("mineKey"),
        Server: []byte("serverKey"),
    }
    jsonData, err := json.Marshal(&original)
    if err != nil {
        t.Fatalf("Error marshalling TrafficKeys: %v", err)
    }
    var decoded TrafficKeys
    err = json.Unmarshal(jsonData, &decoded)
    if err != nil {
        t.Fatalf("Error unmarshalling TrafficKeys: %v", err)
    }
    if string(decoded.Mine) != string(original.Mine) || string(decoded.Server) != string(original.Server) {
        t.Errorf("Decoded TrafficKeys does not match original; got mine=%s, server=%s; want mine=%s, server=%s",
            decoded.Mine, decoded.Server, original.Mine, original.Server)
    }
}