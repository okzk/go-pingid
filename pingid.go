package pingid

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/magiconair/properties"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var client = &http.Client{}

type PingID struct {
	token    string
	orgAlias string
	key      []byte
}

type response struct {
	ResponseBody json.RawMessage `json:"responseBody"`
}

func NewPingIDFromString(str string) (*PingID, error) {
	p, err := properties.LoadString(str)
	if err != nil {
		return nil, err
	}
	return parseProperties(p)
}

func NewPingIDFromFile(file string) (*PingID, error) {
	p, err := properties.LoadFile(file, properties.UTF8)
	if err != nil {
		return nil, err
	}
	return parseProperties(p)
}

func parseProperties(p *properties.Properties) (*PingID, error) {
	ret := new(PingID)
	var ok bool

	if ret.token, ok = p.Get("token"); !ok {
		return nil, errors.New("missing token")
	}

	if ret.orgAlias, ok = p.Get("org_alias"); !ok {
		return nil, errors.New("missing org_alias")
	}

	v, ok := p.Get("use_base64_key")
	if !ok {
		return nil, errors.New("missing use_base64_key")
	}
	k, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	ret.key = k

	return ret, nil
}

func (p *PingID) send(endpoint string, payload interface{}) (json.RawMessage, error) {
	header, err := encode(map[string]string{
		"alg":       "HS256",
		"org_alias": p.orgAlias,
		"token":     p.token,
	})
	if err != nil {
		return nil, err
	}

	body, err := encode(map[string]interface{}{
		"reqHeader": map[string]string{
			"orgAlias":  p.orgAlias,
			"secretKey": p.token,
			"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05.000"),
			"version":   "4.9",
			"locale":    "en",
		},
		"reqBody": payload,
	})
	if err != nil {
		return nil, err
	}

	signature := p.sign(header + "." + body)

	reqBody := []byte(header + "." + body + "." + signature)
	req, err := http.NewRequest("POST",
		"https://idpxnyl3m.pingidentity.com/pingid/rest/4/"+endpoint,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resByte, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	resStr := string(resByte)
	parts := strings.Split(resStr, ".")
	if len(parts) != 3 || p.sign(parts[0]+"."+parts[1]) != parts[2] {
		return nil, errors.New("invalid response")
	}

	resBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	ret := new(response)
	err = json.Unmarshal(resBody, ret)
	if err != nil {
		return nil, err
	}
	return ret.ResponseBody, nil
}

func encode(data interface{}) (string, error) {
	buf, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (p *PingID) sign(data string) string {
	hash := hmac.New(sha256.New, p.key)
	hash.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
