package validateJWT

import (
	"encoding/json"
	"github.com/bashar-saleh/gonanos/nanos"
	"github.com/dgrijalva/jwt-go"
	"log"
	"regexp"
	"testing"
	"time"
)

var failure = "\u2717"
var succeed = "\u2713"

func TestValidateJWT(t *testing.T) {
	t.Run("Given invalid key When validate token Then error is returned with message // invalid//", testInvalidKey)
	t.Run("Given expired token When validate token Then error is returned with message // expired//", testExpiredToken)
	t.Run("Given valid token When validate token Then Claims is returned", testValidToken)

}

func testValidToken(t *testing.T) {
	validKey := "key!@#"
	mailBox := NewValidateJWTNanos(1, 1, validKey)
	resTo := make(chan nanos.Message)
	errTo := make(chan error)
	id := 123
	roles := []string{"admin", "user"}
	token := generateValidToken(id, roles, validKey)

	msg := nanos.Message{
		Content: []byte(token),
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	mailBox <- msg

	select {
	case res := <-resTo:
		msg := res.Content
		var claims Claims
		err := json.Unmarshal(msg, &claims)
		if err != nil {
			t.Fatalf("\t%s\t%v", failure, err)
		}
		if claims.ID == id && claims.Roles[0] == roles[0] && claims.Roles[1] == roles[1] {
			t.Logf("\t%s\t Passed", succeed)
			return
		}
		t.Fatalf("\t%s\t the response is wrong", failure)
	case _ = <-errTo:
		t.Fatalf("\t%s\t no error should be returned", failure)
	case <-time.After(time.Second * 4):
		t.Fatalf("\t%s\t Timeout", failure)
	}
}

func generateValidToken(id int, roles []string, key string) string {
	jwtKey := []byte(key)
	var claims = Claims{
		ID:    id,
		Roles: roles,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * + 5).Unix(),
		},
	}
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	token, err := tkn.SignedString(jwtKey)
	if err != nil {
		log.Fatalf(err.Error())
	}
	return token
}

func testExpiredToken(t *testing.T) {
	validKey := "key!@#"
	mailBox := NewValidateJWTNanos(1, 1, validKey)
	resTo := make(chan nanos.Message)
	errTo := make(chan error)
	id := 123
	roles := []string{"admin", "user"}
	token := generateExpiredToken(id, roles, validKey)

	msg := nanos.Message{
		Content: []byte(token),
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	mailBox <- msg

	select {
	case _ = <-resTo:
		t.Fatalf("\t%s\t there must not be any response", failure)
	case err := <-errTo:
		matched, err := regexp.MatchString("expired", err.Error())
		if err != nil {
			t.Fatalf(err.Error())
		}
		if !matched {
			t.Fatalf("\t%s\t error should contain phrase 'invalid' -- %v", failure, err)
		}
		t.Logf("\t%s\t passed", succeed)
	case <-time.After(time.Second * 4):
		t.Fatalf("\t%s\t Timeout", failure)
	}
}

func generateExpiredToken(id int, roles []string, key string) string {
	jwtKey := []byte(key)
	var claims = Claims{
		ID:    id,
		Roles: roles,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * -5).Unix(),
		},
	}
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	token, err := tkn.SignedString(jwtKey)
	if err != nil {
		log.Fatalf(err.Error())
	}
	return token
}

func testInvalidKey(t *testing.T) {
	invalidKey := "key123"
	validKey := "key!@#"
	mailBox := NewValidateJWTNanos(1, 1, validKey)
	resTo := make(chan nanos.Message)
	errTo := make(chan error)
	id := 123
	roles := []string{"admin", "user"}
	token := generateToken(id, roles, invalidKey)
	msg := nanos.Message{
		Content: []byte(token),
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	mailBox <- msg

	select {
	case _ = <-resTo:
		t.Fatalf("\t%s\t there must not be any response", failure)
	case err := <-errTo:
		matched, err := regexp.MatchString("invalid", err.Error())
		if err != nil {
			t.Fatalf(err.Error())
		}
		if !matched {
			t.Fatalf("\t%s\t error should contain phrase 'invalid' -- %v", failure, err)
		}
		t.Logf("\t%s\t passed", succeed)
	case <-time.After(time.Second * 4):
		t.Fatalf("\t%s\t Timeout", failure)
	}
}

func generateToken(id int, roles []string, key string) string {
	jwtKey := []byte(key)
	var claims = Claims{
		ID:    id,
		Roles: roles,
	}
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	token, err := tkn.SignedString(jwtKey)
	if err != nil {
		log.Fatalf(err.Error())
	}
	return token
}
