package jwt

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/webcore-go/webcore/app/config"
	"github.com/webcore-go/webcore/app/loader"
	"github.com/webcore-go/webcore/app/loader/auth"
	"github.com/webcore-go/webcore/lib/auth/authn"
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

func (a *JWTAuthLoader) Init(args ...any) (loader.Library, error) {
	config := args[1].(config.AuthConfig)

	authn := &authn.AuthN{}
	authn.SetValidator(&JWTAuthValidator{SecretKey: config.SecretKey})
	err := authn.Install(args...)
	if err != nil {
		return nil, err
	}

	return authn, nil
}

type JWTAuthValidator struct {
	Header    string
	SecretKey string
	Prefix    string
	Key       string
}

func (a *JWTAuthValidator) Name() string {
	return "basic"
}

func (a *JWTAuthValidator) ValidateKey(ctx *fiber.Ctx) error {
	var tokenString string

	// Coba dapatkan dari Authorization
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("Authorization header required")
	}

	// konten dimulai dengan prefiks "Bearer "
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		return fmt.Errorf("Required prefix in Authorization header is missing")
	}

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

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Store user info in context
		ctx.Locals("user_id", claims["user_id"])
		ctx.Locals("user_role", claims["role"])
		ctx.Locals("user_permissions", claims["permissions"])
		ctx.Locals("auth_type", "jwt")

		rbac, ok1 := userInfo.(*auth.UserAuthInfoRBAC)
		if ok1 {
			return userKey == rbac.UserId, nil
		}

		abac, ok2 := userInfo.(*auth.UserAuthInfoABAC)
		if ok2 {
			return userKey == abac.UserId, nil
		}

		return false, nil
	}

	return true, fmt.Errorf("Invalid token claims")
}
