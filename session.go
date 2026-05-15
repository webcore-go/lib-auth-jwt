package jwt

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/webcore-go/webcore/infra/config"
	"github.com/webcore-go/webcore/port/auth"
)

type JWTSession struct {
	Config  config.AuthConfig
	Session auth.ISessionStore
}

func (s *JWTSession) SetSessionStore(session auth.ISessionStore) {
	s.Session = session
}

func (s *JWTSession) Login(ctx *fiber.Ctx, userInfo auth.IUserAuthInfo) (*auth.UserLoginInfo, error) {
	var refresh *string
	rbac, ok := userInfo.(*auth.UserAuthInfoRBAC)
	if ok {
		if rbac.Username == nil {
			return nil, fmt.Errorf("Username null")
		}

		token, err := s.createJWT(*rbac.Username, rbac.Groups, rbac.Roles, s.Config.Session.ExpiresIn)
		if err != nil {
			return nil, err
		}

		if s.Session != nil {
			rt, err := s.createJWT(*rbac.Username, rbac.Groups, rbac.Roles, s.Config.Session.RefreshIn)
			if err != nil {
				return nil, err
			}

			refresh = &rt
		}

		loginInfo := &auth.UserLoginInfo{
			Username:     *rbac.Username,
			AccessToken:  &token,
			RefreshToken: refresh,
			ExpiresIn:    s.Config.Session.ExpiresIn,
			RefreshIn:    s.Config.Session.RefreshIn,
			Groups:       rbac.Groups,
			Permissions:  rbac.Roles,
		}

		if s.Session != nil {
			err = s.Session.Save(loginInfo)
			if err != nil {
				return nil, err
			}
		}

		return loginInfo, nil
	} else {
		abac, ok := userInfo.(*auth.UserAuthInfoABAC)
		if ok {
			if abac.Username == nil {
				return nil, fmt.Errorf("Username null")
			}

			token, err := s.createJWT(*abac.Username, abac.Groups, []string{}, s.Config.Session.ExpiresIn)
			if err != nil {
				return nil, err
			}

			if s.Session != nil {
				rt, err := s.createJWT(*abac.Username, abac.Groups, []string{}, s.Config.Session.RefreshIn)
				if err != nil {
					return nil, err
				}

				refresh = &rt
			}

			loginInfo := &auth.UserLoginInfo{
				Username:     *abac.Username,
				AccessToken:  &token,
				RefreshToken: refresh,
				ExpiresIn:    s.Config.Session.ExpiresIn,
				RefreshIn:    s.Config.Session.RefreshIn,
				Groups:       abac.Groups,
				Permissions:  []string{},
			}

			if s.Session != nil {
				err = s.Session.Save(loginInfo)
				if err != nil {
					return nil, err
				}
			}

			return loginInfo, nil
		}
	}

	return nil, fmt.Errorf("UserInfo not valid")
}

func (s *JWTSession) Refresh(ctx *fiber.Ctx, refreshToken string) (*auth.UserLoginInfo, error) {
	if s.Session != nil {
		loginInfo, err := s.Session.GetByRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		token, err := s.createJWT(loginInfo.Username, loginInfo.Groups, loginInfo.Permissions, s.Config.Session.ExpiresIn)
		if err != nil {
			return nil, err
		}

		refresh, err := s.createJWT(loginInfo.Username, loginInfo.Groups, loginInfo.Permissions, s.Config.Session.RefreshIn)
		if err != nil {
			return nil, err
		}

		// Rotasi AccessToken dan RefreshToken bersamaan untuk keamanan tinggi
		loginInfo.AccessToken = &token
		loginInfo.RefreshToken = &refresh

		err = s.Session.Refresh(refreshToken, loginInfo)
		if err != nil {
			return nil, err
		}

		return loginInfo, nil
	}

	return nil, fmt.Errorf("Refresh Token not supported")
}

func (s *JWTSession) Logout(ctx *fiber.Ctx, accessToken string) error {
	if s.Session != nil {
		loginInfo, err := s.Session.GetByAccessToken(accessToken)
		if err != nil {
			return err
		}

		return s.Session.Delete(loginInfo)
	}

	return fmt.Errorf("Logout not supported")
}

func (s *JWTSession) createJWT(username string, groups []string, permissions []string, expires time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":          username,
		"user_role":        groups,
		"user_permissions": permissions,
		"exp":              time.Now().Add(expires).Unix(), // Token expired dalam 3 hari
	})

	return token.SignedString([]byte(s.Config.SecretKey))
}
