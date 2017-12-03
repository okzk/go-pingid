package pingid

import (
	"encoding/json"
)

type AuthenticateResponse struct {
	ClientData  string `json:"clientData"`
	ErrorID     int    `json:"errorId"`
	ErrorMsg    string `json:"errorMsg"`
	SessionID   string `json:"sessionId"`
	UniqueMsgID string `json:"uniqueMsgId"`
}

func (p *PingID) AuthenticateOnline(userName, clientData string) (*AuthenticateResponse, error) {
	payload := map[string]string{
		"userName": userName,
		"authType": "CONFIRM",
		"spAlias":  "web",
	}
	if clientData != "" {
		payload["clientData"] = clientData
	}

	resBody, err := p.send("authonline/do", payload)
	if err != nil {
		return nil, err
	}

	ret := new(AuthenticateResponse)
	err = json.Unmarshal(resBody, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (p *PingID) AuthenticateOffline(sessionID, userName, otp, clientData string) (*AuthenticateResponse, error) {
	payload := map[string]string{
		"otp":       otp,
		"userName":  userName,
		"sessionId": sessionID,
		"spAlias":   "web",
	}
	if clientData != "" {
		payload["clientData"] = clientData
	}

	resBody, err := p.send("authoffline/do", payload)
	if err != nil {
		return nil, err
	}

	ret := new(AuthenticateResponse)
	err = json.Unmarshal(resBody, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (a *AuthenticateResponse) Success() bool {
	return a.ErrorID == 200
}
