package registerUser

import (
	"auth-nanos/datastores"
	"auth-nanos/entities"
	"encoding/binary"
	"github.com/bashar-saleh/gonanos/nanos"
	"testing"
	"time"
)

var failure = "\u2717"
var succeed = "\u2713"

func TestRegisterNewUser(t *testing.T) {

	data := []struct {
		user                    entities.User
		id                      int64
		nameValidationRules     []func(name string) (bool, string)
		usernameValidationRules []func(username string) (bool, string)
		passwordValidationRules []func(password string) (bool, string)
		emailValidationRules    []func(email string) (bool, string)
		phoneValidationRules    []func(phone string) (bool, string)
	}{
		{
			user: entities.User{
				Name:     "Bashaleh",
				Email:    "example@",
				Phone:    "+999999",
				Password: "123123!@",
				Username: "Xandaleh",
				Roles:    []string{"Admin", "Customer"},
			},
			id: 1,
			nameValidationRules: []func(name string) (b bool, s string){
				func(name string) (b bool, s string) {
					if len(name) > 10 {
						return false, "name length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (b bool, s string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "password length is more than 10"
					}
					return true, ""
				},
			},
			emailValidationRules: []func(email string) (b bool, s string){
				func(email string) (b bool, s string) {
					if len(email) > 10 {
						return false, "email length is more than 10"
					}
					return true, ""
				},
			},
			usernameValidationRules: []func(username string) (b bool, s string){
				func(username string) (b bool, s string) {
					if len(username) > 10 {
						return false, "username length is more than 10"
					}
					return true, ""
				},
			},
			phoneValidationRules: []func(phone string) (b bool, s string){
				func(phone string) (b bool, s string) {
					if len(phone) > 10 {
						return false, "phone length is more than 10"
					}
					return true, ""
				},
			},
		},
		{
			user: entities.User{
				Name:     "Bashaleh",
				Email:    "example@asdasdasd",
				Phone:    "+999999",
				Password: "123123!@",
				Username: "Xandaleh",
				Roles:    []string{"Admin", "Customer"},
			},
			id: 1,
			nameValidationRules: []func(name string) (b bool, s string){
				func(name string) (b bool, s string) {
					if len(name) > 10 {
						return false, "name length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (b bool, s string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "password length is more than 10"
					}
					return true, ""
				},
			},
			emailValidationRules: []func(email string) (b bool, s string){
				func(email string) (b bool, s string) {
					if len(email) > 10 {
						return false, "email length is more than 10"
					}
					return true, ""
				},
			},
			usernameValidationRules: []func(username string) (b bool, s string){
				func(username string) (b bool, s string) {
					if len(username) > 10 {
						return false, "username length is more than 10"
					}
					return true, ""
				},
			},
			phoneValidationRules: []func(phone string) (b bool, s string){
				func(phone string) (b bool, s string) {
					if len(phone) > 10 {
						return false, "phone length is more than 10"
					}
					return true, ""
				},
			},
		},
		{
			user: entities.User{
				Name:     "Bashaleh",
				Email:    "example@",
				Phone:    "+9999999999999",
				Password: "123123!@",
				Username: "Xandaleh",
				Roles:    []string{"Admin", "Customer"},
			},
			id: 1,
			nameValidationRules: []func(name string) (b bool, s string){
				func(name string) (b bool, s string) {
					if len(name) > 10 {
						return false, "name length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (b bool, s string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "password length is more than 10"
					}
					return true, ""
				},
			},
			emailValidationRules: []func(email string) (b bool, s string){
				func(email string) (b bool, s string) {
					if len(email) > 10 {
						return false, "email length is more than 10"
					}
					return true, ""
				},
			},
			usernameValidationRules: []func(username string) (b bool, s string){
				func(username string) (b bool, s string) {
					if len(username) > 10 {
						return false, "username length is more than 10"
					}
					return true, ""
				},
			},
			phoneValidationRules: []func(phone string) (b bool, s string){
				func(phone string) (b bool, s string) {
					if len(phone) > 10 {
						return false, "phone length is more than 10"
					}
					return true, ""
				},
			},
		},
		{
			user: entities.User{
				Name:     "Bashaleh",
				Email:    "example@",
				Phone:    "+999999",
				Password: "123123!@asdasdasd",
				Username: "Xandaleh",
				Roles:    []string{"Admin", "Customer"},
			},
			id: 1,
			nameValidationRules: []func(name string) (b bool, s string){
				func(name string) (b bool, s string) {
					if len(name) > 10 {
						return false, "name length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (b bool, s string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "password length is more than 10"
					}
					return true, ""
				},
			},
			emailValidationRules: []func(email string) (b bool, s string){
				func(email string) (b bool, s string) {
					if len(email) > 10 {
						return false, "email length is more than 10"
					}
					return true, ""
				},
			},
			usernameValidationRules: []func(username string) (b bool, s string){
				func(username string) (b bool, s string) {
					if len(username) > 10 {
						return false, "username length is more than 10"
					}
					return true, ""
				},
			},
			phoneValidationRules: []func(phone string) (b bool, s string){
				func(phone string) (b bool, s string) {
					if len(phone) > 10 {
						return false, "phone length is more than 10"
					}
					return true, ""
				},
			},
		},
		{
			user: entities.User{
				Name:     "Bashaleh",
				Email:    "example@",
				Phone:    "+999999",
				Password: "123123!@",
				Username: "Xandalehasdasdasd",
				Roles:    []string{"Admin", "Customer"},
			},
			id: 1,
			nameValidationRules: []func(name string) (b bool, s string){
				func(name string) (b bool, s string) {
					if len(name) > 10 {
						return false, "name length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (b bool, s string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "password length is more than 10"
					}
					return true, ""
				},
			},
			emailValidationRules: []func(email string) (b bool, s string){
				func(email string) (b bool, s string) {
					if len(email) > 10 {
						return false, "email length is more than 10"
					}
					return true, ""
				},
			},
			usernameValidationRules: []func(username string) (b bool, s string){
				func(username string) (b bool, s string) {
					if len(username) > 10 {
						return false, "username length is more than 10"
					}
					return true, ""
				},
			},
			phoneValidationRules: []func(phone string) (b bool, s string){
				func(phone string) (b bool, s string) {
					if len(phone) > 10 {
						return false, "phone length is more than 10"
					}
					return true, ""
				},
			},
		},
	}

	for i := range data {
		t.Logf("\ttesting User: %v ", data[i].user)
		{
			db := datastores.SqliteConnection()

			mailBox := NewRegisterUserNanos(
				1,
				1000,
				db,
				data[i].nameValidationRules,
				data[i].usernameValidationRules,
				data[i].passwordValidationRules,
				data[i].emailValidationRules,
				data[i].phoneValidationRules,
			)

			var resTo = make(chan nanos.Message)
			var errTo = make(chan error)
			content, err := data[i].user.ToByte()
			if err != nil {
				t.Fatal(err)
			}

			mailBox <- nanos.Message{
				Content: content,
				ResTo:   resTo,
				ErrTo:   errTo,
			}

			select {
			case resMsg := <-resTo:
				var id = int64(binary.LittleEndian.Uint64(resMsg.Content))
				if id != data[i].id {
					t.Logf("\t\t%s\t [False] - data[%v].id != %v", failure, data[i].id, id)
				}
				t.Logf("\t\t%s\t [Pass]", succeed)
			case errMsg := <-errTo:
				t.Logf("\t\t%s\t [Error] - data[%v] - %s", failure, i, errMsg)

			case <-time.After(time.Second * 2):
				t.Logf("\t\t%s\t [Timeout] - data[%v] ", failure, i)

			}
		}
	}
}
