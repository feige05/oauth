package oauth2

import (
	"fmt"
	"net/url"
)

// type Endpoint interface {
// 	ExchangeTokenURL(code string) string        // 通过code换取access_token的地址
// 	RefreshTokenURL(refreshToken string) string // 刷新access_token的地址
// }
type Endpoint struct {
	ClientID      string
	ClientSecret  string
	CallbackURI   string
	OtherLoginURI string
}

// AuthCodeURL 生成网页授权地址.
// response_type 必须  授权类型，此值固定为“code”。
// client_id 必须  申请QQ登录成功后，分配给应用的appid。
// redirect_uri  必须  成功授权后的回调地址，必须是注册appid时填写的主域名下的地址，建议设置为网站首页或网站的用户中心。注意需要将url进行URLEncode。
// state 必须  client端的状态值。用于第三方应用防止CSRF攻击，成功授权后回调时会原样带回。请务必严格按照流程检查用户与state参数状态的绑定。
// scope 可选  请求用户授权时向用户显示的可进行授权的列表。
// 可填写的值是API文档中列出的接口，以及一些动作型的授权（目前仅有：do_like），如果要填写多个接口名称，请用逗号隔开。
// 例如：scope=get_user_info,list_album,upload_pic,do_like
// 不传则默认请求对接口get_user_info进行授权。
// 建议控制授权项的数量，只传入必要的接口名称，因为授权项越多，用户越可能拒绝进行任何授权。
// display 可选  仅PC网站接入时使用。
// 用于展示的样式。不传则默认展示为PC下的样式。
// 如果传入“mobile”，则展示为mobile端下的样式。
// g_ut  可选  仅WAP网站接入时使用。
// QQ登录页面版本（1：wml版本； 2：xhtml版本），默认值为1。
func (p *Endpoint) AuthCodeURL(State string) string {
	return fmt.Sprintf("https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s", p.ClientID, p.CallbackURI, url.QueryEscape(State))
}

func (p *Endpoint) ExchangeTokenURL(code string) string {
	return fmt.Sprintf("https://graph.qq.com/oauth2.0/token?grant_type=authorization_code&client_id=%s&client_secret=%s&code=%s&redirect_uri=%s", p.ClientID, p.ClientSecret, url.QueryEscape(code), p.CallbackURI)
}
func (p *Endpoint) RefreshTokenURL(refreshToken string) string {
	return fmt.Sprintf("https://graph.qq.com/oauth2.0/token?grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s", p.ClientID, p.ClientSecret, url.QueryEscape(refreshToken))
}
func (p *Endpoint) OpenIdURL(accessToken string) string {
	return fmt.Sprintf("https://graph.qq.com/oauth2.0/me?access_token=%s", url.QueryEscape(accessToken))
}
func (p *Endpoint) UserInfoURL(accessToken, openid string) string {
	return fmt.Sprintf("https://graph.qq.com/user/get_user_info?access_token=%s&oauth_consumer_key=%s&openid=%s", url.QueryEscape(accessToken), p.ClientID, url.QueryEscape(openid))
}
