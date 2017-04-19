package oauth2

import (
	"time"

	log "github.com/goinggo/tracelog"
)

type TokenStorage interface {
	Data() (*Token, error)
	Put(*Token) error
}

type Token struct {
	AccessToken  string `json:"access_token"`            // 网页授权接口调用凭证
	CreatedAt    int64  `json:"created_at"`              // access_token 创建时间, unixtime, 分布式系统要求时间同步, 建议使用 NTP
	ExpiresIn    int64  `json:"expires_in"`              // access_token 接口调用凭证超时时间, 单位: 秒
	RefreshToken string `json:"refresh_token,omitempty"` // 刷新 access_token 的凭证

	OpenID  string `json:"openid,omitempty"`
	UnionID string `json:"unionid,omitempty"`
	Scope   string `json:"scope,omitempty"` // 用户授权的作用域, 使用逗号(,)分隔
}

// Expired 判断 token.AccessToken 是否过期, 过期返回 true, 否则返回 false.
func (token *Token) Expired() bool {
	if token == nil {
		log.Trace("token", "Expired", "token empty")
		return true
	}
	log.Trace("token", "Expired", "now[%d] ,CreateAt[%d],ExpiresIn[%d],use[%d]", time.Now().Unix(), token.CreatedAt, token.ExpiresIn, token.CreatedAt+token.ExpiresIn)
	return time.Now().Unix() >= token.CreatedAt+token.ExpiresIn
}
