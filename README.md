# oauth
qq 第三方登录
# 示例
 ```
 package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth/qq/oauth2"

	log "github.com/goinggo/tracelog"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/pborman/uuid"
)

var (
	// Hash keys should be at least 32 bytes long
	hashKey = []byte("12345678901234567890123456789012")
	// Block keys should be 16 bytes (AES-128) or 32 bytes (AES-256) long.
	// Shorter keys may weaken the encryption used.
	blockKey = []byte("1234567890123456")
	s        = securecookie.New(hashKey, blockKey)

	oauth2Client *oauth2.Client
)

type StateCookie struct {
	Type    string `json:"type"`
	State   string `json:"state"`
	Referer string `json:"referer"`
}

func init() {
	oauth2Client = new(oauth2.Client)
	oauth2Client.ClientID = url.QueryEscape("你的QQClientID")
	oauth2Client.ClientSecret = url.QueryEscape("你的QQSecret")
	oauth2Client.CallbackURI = url.QueryEscape("http://你的回调地址/qq/callback")
	oauth2Client.OtherLoginURI = "你的用户信息持久化地址"
}

//定义用户信息持久化接口返回的数据格式
type OtherLoginResult struct {
    ...
}
func OtherLogin(otherUserid, otherType, nickName, imgUrl, source string) (*OtherLoginResult, []*http.Cookie, error) {
    http.DefaultClient.Post(oauth2Client.OtherLoginURI,.......)
}

func userLogin(token *oauth2.Token, w gin.ResponseWriter) (*OtherLoginResult, error) {
	if openID, err := oauth2Client.GetOpenID(token.AccessToken); err != nil {
		log.Trace("CallBackHandler", "openID", "err:%v", err)
		return nil, err
	} else {
		log.Trace("", "CallBackHandler", "OpenId: %+v\r\n", openID)
		token.OpenID = openID
	}
	userinfo, err := oauth2Client.GetUserInfo(token.AccessToken, token.OpenID)

	if err != nil {
		log.Trace("CallBackHandler", "userinfo", "err:%v", err)
		return nil, err
	}

	var imgUrl string
	if userinfo.FigureurlQq2 != "" {
		imgUrl = userinfo.FigureurlQq2
	} else {
		imgUrl = userinfo.FigureurlQq1
	}
	if result, cookies, err := OtherLogin(token.OpenID, "qq", userinfo.Nickname, imgUrl, "pc"); err != nil {
		log.Trace("CallBackHandler", "OtherLogin", "err:%v", err)
		return nil, err
	} else {
		log.Trace("CallBackHandler", "OtherLogin", "cookies:%v", cookies)
		if encoded, err := s.Encode("o_t_i", token); err == nil {
			cookie := &http.Cookie{}
			cookie.Name = "o_t_i"
			cookie.Value = encoded
			cookie.Secure = false
			cookie.HttpOnly = true
			d := time.Duration(token.ExpiresIn) * time.Second
			cookie.Expires = time.Now().Add(d)
			http.SetCookie(w, cookie)
		} else {
			log.Trace("CallBackHandler", "encode", "token, err:%v", err)
		}
		
		return result, err
	}
}

func LoginHandler(c *gin.Context) {
	state := uuid.New()
	referer := c.Request.Referer()
	value := &StateCookie{
		"qq",
		state,
		referer,
	}
    //保存登录前的信息（一般保存在session中，此处为保存为加密的cookie）
	if encoded, err := s.Encode("oauth_sid", value); err == nil {
		c.SetCookie("oauth_sid", encoded, 60*60*24, "/", "", false, true)
	} else {
		log.Trace("LoginHandler", "encode", "err:%v", err)
	}
	var token *oauth2.Token
	if cookie, err := c.Cookie("o_t_i"); err == nil {
		if err := s.Decode("o_t_i", cookie, &token); err != nil {
			log.Trace("LoginHandler", "decode", "err:%v", err)
		} else {
			log.Trace("LoginHandler", "decode", "Token.AccessToken[%s];Token.RefreshToken[%s]", token.AccessToken, token.RefreshToken)
		}
	} else {
		log.Trace("LoginHandler", "Get Old Token", "err:%v", err)
	}
	AuthCodeURL := oauth2Client.AuthCodeURL(state)
	log.Trace("LoginHandler", "", "AuthCodeURL:%s", AuthCodeURL)
	if exp := token.Expired(); exp {
		c.Redirect(http.StatusFound, AuthCodeURL)
	} else {
		if token, err := oauth2Client.RefreshToken(token.RefreshToken); err == nil {
			log.Trace("LoginHandler", "decode", "Token.AccessToken[%s];Token.RefreshToken[%s]", token.AccessToken, token.RefreshToken)

			if result, err := userLogin(token, c.Writer); err == nil {
				c.JSON(200, gin.H{"code": 1, "msg": "登录成功", "data": result})
			} else {
				c.Redirect(http.StatusFound, AuthCodeURL)
			}
		}
	}
}

// 授权后回调页面
func CallBackHandler(c *gin.Context) {

	log.Trace("CallBackHandler", "requestURI:", c.Request.RequestURI)
	var stateCookie StateCookie
	var errRes = gin.H{"code": 0, "msg": "登录失败"}

    //取出登录前的信息，做校验（一般保存在session中）
	if cookie, err := c.Cookie("oauth_sid"); err != nil {
		log.Trace("CallBackHandler", "cookie", "err:%v", err)
		c.JSON(200, errRes)
		return
	} else if err := s.Decode("oauth_sid", cookie, &stateCookie); err != nil {
		log.Trace("CallBackHandler", "decode", "err:%v", err)
		c.JSON(200, errRes)
		return
	}

	savedState := stateCookie.State // 取出保存的state

	code := c.Query("code")
	if code == "" {
		log.Trace("CallBackHandler", "", "用户禁止授权")
		c.JSON(200, errRes)
		return
	}

	queryState := c.Query("state")
	if queryState == "" {
		log.Trace("CallBackHandler", "", "state 参数为空")
		c.JSON(200, errRes)
		return
	}
	if savedState != queryState {
		str := fmt.Sprintf("state 不匹配, session 中的为 %q, url 传递过来的是 %q", savedState, queryState)
		log.Trace("CallBackHandler", "", str)
		c.JSON(200, errRes)
		return
	}

	token, err := oauth2Client.GetToken(code)
	if err != nil || token == nil {
		log.Trace("CallBackHandler", "token", "err:%v", err)
		c.JSON(200, errRes)
		return
	}

	log.Trace("", "CallBackHandler", "token: %+v\r\n", token)

	if result, err := userLogin(token, c.Writer); err == nil {
		c.JSON(200, gin.H{"code": 1, "msg": "done", "data": result})
	} else {
		c.JSON(200, errRes)
	}
	return
}

func main() {
	log.Start(log.LevelTrace)
	// gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.GET("/qq/login", LoginHandler)
	router.GET("/qq/callback", CallBackHandler)
	router.Run(":9099")
	// fmt.Println(http.ListenAndServe(":9099", nil))
}
```
