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
    "os"
)

type AuthType string
type AuthFactoryFunction func(*AuthConfig) Auth

var (
    authTypeToFactoryFunctionMap = make(map[AuthType]AuthFactoryFunction)
)

type Auth interface {
    Authorize(*AuthOptions) error
}

type AuthOptions struct {
    Path       string
    Expires    int64
    Signature  string
}

func RegisterAuth(sourceType AuthType, factory AuthFactoryFunction) {
    authTypeToFactoryFunctionMap[sourceType] = factory
}

func NewAuthWithConfig(config *AuthConfig) Auth {
    factory := authTypeToFactoryFunctionMap[config.Type]
    if factory == nil {
        fmt.Fprintf(os.Stderr, "Unknown auth type: %s\n", config.Type)
        os.Exit(1)
    }
    return factory(config)
}
