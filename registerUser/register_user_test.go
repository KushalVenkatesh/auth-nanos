package registerUser

import (
	"auth-nanos/datastores"
	"auth-nanos/entities"
	"encoding/binary"
	"github.com/bashar-saleh/gonanos/nanos"
	"regexp"
	"testing"
	"time"
)

var failure = "\u2717"
var succeed = "\u2713"



func TestRegisterUser(t *testing.T) {
	t.Run("testValidationRules", testValidationRules)
	t.Run("When register an existed user Then error must be return And contains msg of //exist before//", registerExistedUser)
	t.Run("When register a new user Then the id should be return", registerNewUser)
}

func testValidationRules(t *testing.T) {
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
			db := datastores.SqliteConnection("test.db")

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
					t.Errorf("\t\t%s\t [False] - data[%v].id != %v", failure, data[i].id, id)
				}
				t.Logf("\t\t%s\t [Pass]", succeed)
			case err := <-errTo:
				matched, _ := regexp.MatchString("length", err.Error())
				if !matched {
					t.Errorf("\t\t%s\t [Error] - data[%v] - %s", failure, i, "Nanos should return error msg with phrase // length //")
				}
				t.Logf("\t\t%s\t [Error] - data[%v] - %s", succeed, i, err.Error())

			case <-time.After(time.Second * 2):
				t.Errorf("\t\t%s\t [Timeout] - data[%v] ", failure, i)

			}
		}
	}
}

func registerNewUser(t *testing.T) {
	db := datastores.SqliteConnection("test.db")
	mailBox := NewRegisterUserNanos(1, 2000, db, nil, nil, nil, nil, nil)
	user := entities.User{
		Name:     "Bashar Saleh",
		Username: "Roba",
		Email:    "bashar.saleh.992@gmail.com",
		Phone:    "+963991347770",
		Password: "123123",
		Roles:    []string{"user"},
	}
	var resTo = make(chan nanos.Message)
	var errTo = make(chan error)

	rawUser, _ := user.ToByte()

	mailBox <- nanos.Message{Content: rawUser, ResTo: resTo, ErrTo: errTo,}

	select {
	case _ = <-errTo:
		t.Error("Nanos should not return any error")
	case res := <-resTo:
		id := int64(binary.LittleEndian.Uint64(res.Content))
		if id != 1 {
			t.Error("Nanos should return id 1")
		}
	}

}

func registerExistedUser(t *testing.T) {
	db := datastores.SqliteConnection("test.db")
	mailBox := NewRegisterUserNanos(1, 2000, db, nil, nil, nil, nil, nil)
	user := entities.User{
		Name:     "Bashar Saleh",
		Username: "Roba",
		Email:    "bashar.saleh.992@gmail.com",
		Phone:    "+963991347770",
		Password: "123123",
		Roles:    []string{"user"},
	}
	rawUser, _ := user.ToByte()
	mailBox <- nanos.Message{Content: rawUser}

	newUser := entities.User{
		Name:     "Bashar Saleh",
		Username: "Roba",
		Email:    "bashar.saleh.992@gmail.com",
		Phone:    "+963991347770",
		Password: "123123",
		Roles:    []string{"user"},
	}
	var resTo = make(chan nanos.Message)
	var errTo = make(chan error)

	rawUser, _ = newUser.ToByte()
	mailBox <- nanos.Message{Content: rawUser, ResTo: resTo, ErrTo: errTo,}

	select {
	case _ = <-resTo:
		t.Error("Nanos should not return any response")
	case err := <-errTo:
		matched, _ := regexp.MatchString("exist before", err.Error())
		if !matched {

			t.Error("Nanos should return msg with //exist before//")
		}
	}

}
