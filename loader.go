package jwt

import (
	"github.com/webcore-go/webcore/adapter/auth/authn"
	"github.com/webcore-go/webcore/infra/config"
	"github.com/webcore-go/webcore/port"
)

type JWTAuthLoader struct {
	name string
}

func (a *JWTAuthLoader) SetName(name string) {
	a.name = name
}

func (a *JWTAuthLoader) Name() string {
	return a.name
}

func (a *JWTAuthLoader) Init(args ...any) (port.Library, error) {
	config := args[1].(config.AuthConfig)
	// context := args[0].(*core.AppContext)

	session := &JWTSession{Config: config}
	authn := &authn.AuthN{}
	validator := &JWTAuthValidator{
		ContentType: config.Session.ContentType,
		UsernameKey: config.Session.UsernameKey,
		PasswordKey: config.Session.PasswordKey,
		SecretKey:   config.SecretKey,
		Session:     session,
	}
	authn.SetValidator(validator)
	err := authn.Install(args...)
	if err != nil {
		return nil, err
	}

	session.SetSessionStore(authn.Authenticator.SessionStore.GetSessionStore())

	return authn, nil
}
