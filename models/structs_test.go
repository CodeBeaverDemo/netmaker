package models

import (
"encoding/json"
    "testing"
    "time"
    jwt "github.com/golang-jwt/jwt/v4"
    "fmt"
)

// TestDummy is a simple placeholder test to ensure the test file is set up correctly.
func TestDummy(t *testing.T) {
    t.Log("Dummy test executed")
}
// TestUserNameInCharSet tests the NameInCharSet method for valid and invalid usernames.
func TestUserNameInCharSet(t *testing.T) {
    // valid username: all allowed characters (even uppercase letters, which should be lowercased)
    validUser := &User{UserName: "Alice-123."}
    if validUser.NameInCharSet() != true {
        t.Error("Expected valid username to return true")
    }

    // invalid username: contains a character not in the allowed set ("!")
    invalidUser := &User{UserName: "Bob!"}
    if invalidUser.NameInCharSet() != false {
        t.Error("Expected invalid username to return false")
    }

    // empty username should be considered valid as there are no disallowed characters.
    emptyUser := &User{UserName: ""}
    if emptyUser.NameInCharSet() != true {
        t.Error("Expected empty username to return true")
    }
}

// TestClaimsCreationAndParsing tests that our Claims struct can be embedded in a JWT token and then parsed back.
func TestClaimsCreationAndParsing(t *testing.T) {
    // Create claims with custom fields and registered claims.
    claims := Claims{
        ID:         "testid",
        MacAddress: "00:11:22:33:44:55",
        Network:    "testnet",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
        },
    }

    // Create token using the HS256 signing method.
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    secret := []byte("mysecret")
    tokenString, err := token.SignedString(secret)
    if err != nil {
        t.Fatalf("Failed to sign token: %v", err)
    }

    // Now parse the token
    parsedToken, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })
    if err != nil {
        t.Fatalf("Failed to parse token: %v", err)
    }

    parsedClaims, ok := parsedToken.Claims.(*Claims)
    if !ok || !parsedToken.Valid {
        t.Fatal("Failed to parse claims correctly")
    }

    if parsedClaims.ID != claims.ID {
        t.Errorf("Expected ID %s but got %s", claims.ID, parsedClaims.ID)
    }

    if parsedClaims.MacAddress != claims.MacAddress {
        t.Errorf("Expected MacAddress %s but got %s", claims.MacAddress, parsedClaims.MacAddress)
    }

    if parsedClaims.Network != claims.Network {
        t.Errorf("Expected Network %s but got %s", claims.Network, parsedClaims.Network)
    }
}
// TestExpiredClaims tests that an expired JWT token fails validation by ensuring that a token signed with past expiry is rejected.
func TestExpiredClaims(t *testing.T) {
    // Create claims with expiry time in the past.
    claims := Claims{
        ID:         "expiredid",
        MacAddress: "AA:BB:CC:DD:EE:FF",
        Network:    "expirednet",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    secret := []byte("mysecret")
    tokenString, err := token.SignedString(secret)
    if err != nil {
        t.Fatalf("Failed to sign token: %v", err)
    }

    _, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })
    if err == nil {
        t.Error("Expected error when parsing an expired token, got none")
    }
}

// TestJSONMarshallingAuthParams tests JSON marshalling and unmarshalling of the AuthParams struct.
func TestJSONMarshallingAuthParams(t *testing.T) {
    original := AuthParams{
        MacAddress: "11:22:33:44:55:66",
        ID:         "user123",
        Password:   "secret",
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal AuthParams: %v", err)
    }
    var decoded AuthParams
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal AuthParams: %v", err)
    }
    if decoded != original {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestDisplayKeyJSON tests JSON marshalling and unmarshalling of the DisplayKey struct.
func TestDisplayKeyJSON(t *testing.T) {
    original := DisplayKey{
        Name: "TestKey",
        Uses: 5,
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal DisplayKey: %v", err)
    }
    var decoded DisplayKey
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal DisplayKey: %v", err)
    }
    if decoded != original {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestTelemetryJSON tests JSON marshalling and unmarshalling of the Telemetry struct.
func TestTelemetryJSON(t *testing.T) {
    original := Telemetry{
        UUID:           "uuid-1234",
        LastSend:       time.Now().Unix(),
        TrafficKeyPriv: []byte("private"),
        TrafficKeyPub:  []byte("public"),
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal Telemetry: %v", err)
    }
    var decoded Telemetry
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal Telemetry: %v", err)
    }
    if decoded.UUID != original.UUID || decoded.LastSend != original.LastSend ||
        string(decoded.TrafficKeyPriv) != string(original.TrafficKeyPriv) ||
        string(decoded.TrafficKeyPub) != string(original.TrafficKeyPub) {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestTrafficKeysJSON tests JSON marshalling and unmarshalling of the TrafficKeys struct.
func TestTrafficKeysJSON(t *testing.T) {
    original := TrafficKeys{
        Mine:   []byte("mineKey"),
        Server: []byte("serverKey"),
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal TrafficKeys: %v", err)
    }
    var decoded TrafficKeys
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal TrafficKeys: %v", err)
    }
    if string(decoded.Mine) != string(original.Mine) || string(decoded.Server) != string(original.Server) {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}
// TestHookDetails executes tests for the HookDetails struct by invoking its Hook function.
func TestHookDetails(t *testing.T) {
    hdNil := HookDetails{
        Hook: func() error { return nil },
        Interval: time.Second,
    }
    if err := hdNil.Hook(); err != nil {
        t.Errorf("Expected nil error from hook, got: %v", err)
    }

    expectedErrMsg := "hook error"
    hdErr := HookDetails{
        Hook: func() error { return fmt.Errorf(expectedErrMsg) },
        Interval: time.Second,
    }
    err := hdErr.Hook()
    if err == nil || err.Error() != expectedErrMsg {
        t.Errorf("Expected error '%s' from hook, got: %v", expectedErrMsg, err)
    }
}

// TestSignInReqDtoJSON tests the JSON marshalling and unmarshalling of the SignInReqDto struct.
// This ensures that the FormFields field is correctly preserved.
func TestSignInReqDtoJSON(t *testing.T) {
    original := SignInReqDto{
        FormFields: []FormField{
            {Id: "1", Value: "test"},
            {Id: "2", Value: 123},
        },
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal SignInReqDto: %v", err)
    }
    var decoded SignInReqDto
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SignInReqDto: %v", err)
    }
    if len(decoded.FormFields) != len(original.FormFields) {
        t.Errorf("Expected %d form fields, got %d", len(original.FormFields), len(decoded.FormFields))
    }
}

// TestLicenseLimitsJSON tests the JSON marshalling and unmarshalling of the LicenseLimits struct.
func TestLicenseLimitsJSON(t *testing.T) {
    original := LicenseLimits{
        Servers:  3,
        Users:    10,
        Hosts:    5,
        Clients:  50,
        Networks: 2,
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal LicenseLimits: %v", err)
    }
    var decoded LicenseLimits
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal LicenseLimits: %v", err)
    }
    if decoded != original {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestSsoLoginJSON tests JSON marshalling and unmarshalling of SsoLoginReqDto and SsoLoginResDto.
func TestSsoLoginJSON(t *testing.T) {
    // Test the SsoLoginReqDto struct.
    reqOriginal := SsoLoginReqDto{OauthProvider: "github"}
    reqData, err := json.Marshal(reqOriginal)
    if err != nil {
        t.Fatalf("Failed to marshal SsoLoginReqDto: %v", err)
    }
    var reqDecoded SsoLoginReqDto
    err = json.Unmarshal(reqData, &reqDecoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SsoLoginReqDto: %v", err)
    }
    if reqDecoded.OauthProvider != reqOriginal.OauthProvider {
        t.Errorf("Expected OauthProvider %s but got %s", reqOriginal.OauthProvider, reqDecoded.OauthProvider)
    }

    // Test the SsoLoginResDto struct.
    resOriginal := SsoLoginResDto{User: "Alice", AuthToken: "token123"}
    resData, err := json.Marshal(resOriginal)
    if err != nil {
        t.Fatalf("Failed to marshal SsoLoginResDto: %v", err)
    }
    var resDecoded SsoLoginResDto
    err = json.Unmarshal(resData, &resDecoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SsoLoginResDto: %v", err)
    }
    if resDecoded.User != resOriginal.User || resDecoded.AuthToken != resOriginal.AuthToken {
        t.Errorf("Expected %+v but got %+v", resOriginal, resDecoded)
    }
}

// TestGetClientConfReqDtoJSON tests the JSON marshalling and unmarshalling of the GetClientConfReqDto struct.
func TestGetClientConfReqDtoJSON(t *testing.T) {
    original := GetClientConfReqDto{PreferredIp: "192.168.1.1"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal GetClientConfReqDto: %v", err)
    }
    var decoded GetClientConfReqDto
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal GetClientConfReqDto: %v", err)
    }
    if decoded.PreferredIp != original.PreferredIp {
        t.Errorf("Expected PreferredIp %s but got %s", original.PreferredIp, decoded.PreferredIp)
    }
}
// TestGlobalConfigJSON tests JSON marshalling and unmarshalling for GlobalConfig.
func TestGlobalConfigJSON(t *testing.T) {
    original := GlobalConfig{Name: "TestGlobal"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal GlobalConfig: %v", err)
    }
    var decoded GlobalConfig
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal GlobalConfig: %v", err)
    }
    if decoded.Name != original.Name {
        t.Errorf("Expected Name %s but got %s", original.Name, decoded.Name)
    }
}

// TestErrorResponseJSON tests JSON marshalling and unmarshalling for ErrorResponse.
func TestErrorResponseJSON(t *testing.T) {
    original := ErrorResponse{Code: 404, Message: "Not found"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal ErrorResponse: %v", err)
    }
    var decoded ErrorResponse
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal ErrorResponse: %v", err)
    }
    if decoded.Code != original.Code || decoded.Message != original.Message {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestNodeAuthJSON tests JSON marshalling and unmarshalling for NodeAuth.
func TestNodeAuthJSON(t *testing.T) {
    original := NodeAuth{Network: "testnet", Password: "pass", MacAddress: "00:11:22:33:44:55", ID: "node123"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal NodeAuth: %v", err)
    }
    var decoded NodeAuth
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal NodeAuth: %v", err)
    }
    if decoded.Network != original.Network || decoded.Password != original.Password || 
        decoded.MacAddress != original.MacAddress || decoded.ID != original.ID {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestSuccessResponseJSON tests JSON marshalling and unmarshalling for SuccessResponse.
func TestSuccessResponseJSON(t *testing.T) {
    original := SuccessResponse{Code: 200, Message: "OK", Response: "Success response"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal SuccessResponse: %v", err)
    }
    var decoded SuccessResponse
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SuccessResponse: %v", err)
    }
    if decoded.Code != original.Code || decoded.Message != original.Message || decoded.Response != original.Response {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestRsrcURLInfoJSON tests JSON marshalling and unmarshalling for RsrcURLInfo.
func TestRsrcURLInfoJSON(t *testing.T) {
    original := RsrcURLInfo{Method: "GET", Path: "/api/test"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal RsrcURLInfo: %v", err)
    }
    var decoded RsrcURLInfo
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal RsrcURLInfo: %v", err)
    }
    if decoded.Method != original.Method || decoded.Path != original.Path {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestSsoLoginDataJSON tests JSON marshalling and unmarshalling for SsoLoginData.
func TestSsoLoginDataJSON(t *testing.T) {
    now := time.Now()
    original := SsoLoginData{
        Expiration: now,
        OauthProvider: "google",
        OauthCode: "code123",
        Username: "testuser",
        AmbAccessToken: "ambtoken",
    }
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal SsoLoginData: %v", err)
    }
    var decoded SsoLoginData
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SsoLoginData: %v", err)
    }
    // Use Equal method for time because time equality is tricky.
    if !decoded.Expiration.Equal(original.Expiration) || decoded.OauthProvider != original.OauthProvider ||
        decoded.OauthCode != original.OauthCode || decoded.Username != original.Username ||
        decoded.AmbAccessToken != original.AmbAccessToken {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestLoginReqDtoJSON tests JSON marshalling and unmarshalling for LoginReqDto.
func TestLoginReqDtoJSON(t *testing.T) {
    original := LoginReqDto{Email: "user@example.com", TenantID: "tenant123"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal LoginReqDto: %v", err)
    }
    var decoded LoginReqDto
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal LoginReqDto: %v", err)
    }
    if decoded.Email != original.Email || decoded.TenantID != original.TenantID {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}

// TestSuccessfulUserLoginResponseJSON tests JSON marshalling and unmarshalling for SuccessfulUserLoginResponse.
func TestSuccessfulUserLoginResponseJSON(t *testing.T) {
    original := SuccessfulUserLoginResponse{UserName: "testuser", AuthToken: "token123"}
    data, err := json.Marshal(original)
    if err != nil {
        t.Fatalf("Failed to marshal SuccessfulUserLoginResponse: %v", err)
    }
    var decoded SuccessfulUserLoginResponse
    err = json.Unmarshal(data, &decoded)
    if err != nil {
        t.Fatalf("Failed to unmarshal SuccessfulUserLoginResponse: %v", err)
    }
    if decoded.UserName != original.UserName || decoded.AuthToken != original.AuthToken {
        t.Errorf("Expected %+v but got %+v", original, decoded)
    }
}