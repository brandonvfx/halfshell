// Copyright (c) 2014 
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package halfshell

import (
    "fmt"
    "time"
    "crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
    "errors"
)

const (
    AUTH_TYPE_SIGNED_URL AuthType = "signed_url"
)

type SignedUrlAuth struct {
    Config *AuthConfig
    Logger *Logger
}

func NewSignedUrlAuthWithConfig(config *AuthConfig) Auth {
    return &SignedUrlAuth{
        Config: config,
        Logger: NewLogger("auth.signed_url.%s", config.Name),
    }
}

func (s *SignedUrlAuth) Authorize(request *AuthOptions) error {
    current_time := time.Now().UTC().Unix()
    if request.Expires < current_time {
        s.Logger.Warn("Url Expired.")
        return errors.New("Url Expired.")
    }
    
    string_to_sign := fmt.Sprintf("GET\n%d\n%s", request.Expires, request.Path)
    h := hmac.New(sha256.New, []byte(s.Config.SecretKey))
	h.Write([]byte(string_to_sign))
	sig := make([]byte, base64.StdEncoding.EncodedLen(h.Size()))
	base64.StdEncoding.Encode(sig, h.Sum(nil))

    if request.Signature != string(sig) {
        s.Logger.Warn("Signature did not match")
        return errors.New("Signature did not match")
    }
    
    s.Logger.Info("Request Authorized.")
    return nil
}

func init() {
    RegisterAuth(AUTH_TYPE_SIGNED_URL, NewSignedUrlAuthWithConfig)
}
