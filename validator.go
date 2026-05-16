package jwt

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/webcore-go/webcore/infra/logger"
	"github.com/webcore-go/webcore/port/auth"
)

type JWTAuthValidator struct {
	ContentType string
	UsernameKey string
	PasswordKey string
	SecretKey   string
	Key         string
	Session     auth.IAuthSession
}

func (a *JWTAuthValidator) Name() string {
	return "jwt"
}

func (a *JWTAuthValidator) IsRequireLogin() bool {
	return true
}

func (a *JWTAuthValidator) GetAuthSession() auth.IAuthSession {
	return a.Session
}

func (a *JWTAuthValidator) ValidateKey(ctx *fiber.Ctx) error {
	var tokenString string

	// Coba dapatkan dari Authorization
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("Authorization header required")
	}

	// konten dimulai dengan prefiks "Bearer "
	if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
		tokenString = after
	} else {
		return fmt.Errorf("Required prefix in Authorization header is missing")
	}

	logger.Debug("JWT", "TOKEN", tokenString)
	a.Key = tokenString
	return nil
}

func (a *JWTAuthValidator) GetValue() string {
	return a.Key
}

func (a *JWTAuthValidator) VerifyUser(ctx *fiber.Ctx, userKey string, userInfo auth.IUserAuthInfo) (bool, error) {
	if userKey == "" {
		return false, nil
	}

	// Parse and validate token
	token, err := jwt.Parse(userKey, func(token *jwt.Token) (any, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte(a.SecretKey), nil
	})

	if err != nil {
		return true, fmt.Errorf("Invalid or expired token")
	}

	logger.DebugJson("JWT CLAIMS", token)
	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		usr, ok := claims["user_id"]
		if !ok {
			return true, fmt.Errorf("JWT Claim data invalid")
		}

		username := usr.(string)
		rbac, ok1 := userInfo.(*auth.UserAuthInfoRBAC)
		if ok1 {
			if rbac.Username != nil && username == *rbac.Username {
				// Store user info in context
				ctx.Locals("user_id", username)
				ctx.Locals("user_role", claims["role"])
				ctx.Locals("user_permissions", claims["permissions"])
				ctx.Locals("auth_type", "jwt")

				return true, nil
			}
		} else {
			abac, ok2 := userInfo.(*auth.UserAuthInfoABAC)
			if ok2 {
				if abac.Username != nil && username == *abac.Username {
					// Store user info in context
					ctx.Locals("user_id", username)
					ctx.Locals("user_role", claims["role"])
					ctx.Locals("user_permissions", claims["permissions"])
					ctx.Locals("auth_type", "jwt")

					return true, nil
				}
			}
		}

		return false, nil
	}

	return true, fmt.Errorf("Invalid token claims")
}
