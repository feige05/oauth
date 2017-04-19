package oauth2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	netUrl "net/url"
	"strconv"
	"time"

	log "github.com/goinggo/tracelog"
)

type UserInfo struct {
	Ret             int    `json:"ret"`
	Msg             string `json:"msg"`
	Nickname        string `json:"nickname"`
	Figureurl       string `json:"figureurl"`
	Figureurl1      string `json:"figureurl_1"`
	Figureurl2      string `json:"figureurl_2"`
	FigureurlQq1    string `json:"figureurl_qq_1"`
	FigureurlQq2    string `json:"figureurl_qq_2"`
	Gender          string `json:"gender"`
	IsYellowVip     string `json:"is_yellow_vip"`
	Vip             string `json:"vip"`
	YellowVipLevel  string `json:"yellow_vip_level"`
	Level           string `json:"level"`
	IsYellowYearVip string `json:"is_yellow_year_vip"`
}
type Result struct {
	Error
	Token
}

func DecodeJSONHttpResponse(r io.Reader, v interface{}) error {

	body, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	body2 := body
	buf := bytes.NewBuffer(make([]byte, 0, len(body2)+1024))
	if err := json.Indent(buf, body2, "", "    "); err == nil {
		body2 = buf.Bytes()
	}
	log.Trace("api", "DecodeJSONHttpResponse", "http response body:\n%s\n", body2)

	return json.Unmarshal(body, v)
}
func (clt *Client) token(body *[]byte) (token *Token, err error) {
	result := &Result{}
	token = new(Token)
	var query string
	var m netUrl.Values

	query = string(*body)

	//access_token=E2298866C61EEA38F8CFDF466092E1BD&expires_in=7776000&refresh_token=4878F0BFF9D8CEA783F4DA6957C795CE
	//callback( {"error":100020,"error_description":"code is reused error"} );
	log.Trace("api", "DecodeJSONHttpResponse", "http response body:\n%s\n", query)
	m, err = netUrl.ParseQuery(query)

	if err == nil {
		result.AccessToken = m.Get("access_token")
		result.RefreshToken = m.Get("refresh_token")
		if exp := m.Get("expires_in"); exp != "" {
			result.ExpiresIn, err = strconv.ParseInt(exp, 10, 64)
		}
		if code := m.Get("code"); code != "" {
			result.ErrCode, err = strconv.ParseInt(code, 10, 64)
		}
		result.ErrMsg = m.Get("msg")
	} else {
		return nil, err
	}
	// if err = DecodeJSONHttpResponse(httpResp.Body, &result); err != nil {
	// 	return
	// }
	if result.ErrCode != ErrCodeOK {
		return nil, &result.Error
	}

	// 过期时间提前
	switch {
	case result.ExpiresIn > 31556952: // 60*60*24*365.2425
		return nil, errors.New("expires_in too large: " + strconv.FormatInt(result.ExpiresIn, 10))
	case result.ExpiresIn > 60*60:
		result.ExpiresIn -= 60 * 20
	case result.ExpiresIn > 60*30:
		result.ExpiresIn -= 60 * 10
	case result.ExpiresIn > 60*15:
		result.ExpiresIn -= 60 * 5
	case result.ExpiresIn > 60*5:
		result.ExpiresIn -= 60
	case result.ExpiresIn > 60:
		result.ExpiresIn -= 20
	default:
		return nil, errors.New("expires_in too small: " + strconv.FormatInt(result.ExpiresIn, 10))
	}

	token.AccessToken = result.AccessToken
	token.CreatedAt = time.Now().Unix()
	token.ExpiresIn = result.ExpiresIn
	if result.RefreshToken != "" {
		token.RefreshToken = result.RefreshToken
	}
	if result.OpenID != "" {
		token.OpenID = result.OpenID
	}
	if result.UnionID != "" {
		token.UnionID = result.UnionID
	}
	if result.Scope != "" {
		token.Scope = result.Scope
	}
	return
}

// GetToken 获取 Token
func (clt *Client) GetToken(code string) (*Token, error) {

	httpResp, err := clt.httpClient().Get(clt.ExchangeTokenURL(code))
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http.Status: %s", httpResp.Status)
	}

	body, err := ioutil.ReadAll(httpResp.Body)

	if err != nil {
		return nil, err
	} else {
		return clt.token(&body)
	}
}

// RefreshToken 刷新 access_token.
//  NOTE:
//  1. refreshToken 可以为空.
//  2. 返回的 token == clt.Token
func (clt *Client) RefreshToken(refreshToken string) (*Token, error) {
	httpResp, err := clt.httpClient().Get(clt.RefreshTokenURL(refreshToken))
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		err = fmt.Errorf("http.Status: %s", httpResp.Status)
		return nil, err
	}

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	return clt.token(&body)

}

func (clt *Client) GetOpenID(accessToken string) (string, error) {
	url := clt.OpenIdURL(accessToken)
	result := &Result{}
	// var query string

	httpResp, err := clt.httpClient().Get(url)
	if err != nil {
		return "", err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// log.Printf("http response body:\n%s\n", query)
		return "", err
	}

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return "", err
	}
	log.Trace("api", "GetOpenID", "http response body:\n%s\n", string(body))
	if err := json.Unmarshal(body[10:len(body)-3], result); err == nil {
		return result.OpenID, nil
	} else {
		return "", err
	}

}
func (clt *Client) GetUserInfo(accessToken, openID string) (*UserInfo, error) {
	url := clt.UserInfoURL(accessToken, openID)
	result := &UserInfo{}
	// var query string

	httpResp, err := clt.httpClient().Get(url)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// log.Printf("http response body:\n%s\n", query)
		return nil, err
	}

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	// log.Printf("url: %s; http response body:\n%s\n", url, string(body))
	if err := json.Unmarshal(body, result); err == nil {
		return result, nil
	} else {
		return nil, err
	}

}
