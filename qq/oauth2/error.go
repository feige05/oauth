package oauth2

import (
	"fmt"
)

const (
	ErrCodeOK = 0
)

type Error struct {
	ErrCode int64  `json:"code"`
	ErrMsg  string `json:"msg"`
}

func (err *Error) Error() string {
	return fmt.Sprintf("errcode: %d, errmsg: %s", err.ErrCode, err.ErrMsg)
}
