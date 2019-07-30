package signinUser

import (
	"encoding/json"
	"github.com/bashar-saleh/auth-nanos/datastores"
	"github.com/bashar-saleh/gonanos/nanos"
	"regexp"
	"testing"
	"time"
)

var succeed = "\u2713"
var failure = "\u2717"

func TestSigninUser(t *testing.T) {
	t.Run("testValidationRules", testValidationRules)
}

func testValidationRules(t *testing.T) {
	data := []struct {
		signinData struct {
			FirstField string
			Password   string
		}
		firstFieldValidationRules []func(firstField string) (bool, string)
		passwordValidationRules   []func(password string) (bool, string)
	}{
		{
			signinData: struct {
				FirstField string
				Password   string
			}{FirstField: "example@gmail.com", Password: "156789"},
			firstFieldValidationRules: []func(firstField string) (bool, string){
				func(firstField string) (b bool, s string) {
					if len(firstField) > 10 {
						return false, "FirstField length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (bool, string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "Password length is more than 10"
					}
					return true, ""
				},
			},
		},
		{
			signinData: struct {
				FirstField string
				Password   string
			}{FirstField: "example", Password: "156712312312389"},
			firstFieldValidationRules: []func(firstField string) (bool, string){
				func(firstField string) (b bool, s string) {
					if len(firstField) > 10 {
						return false, "FirstField length is more than 10"
					}
					return true, ""
				},
			},
			passwordValidationRules: []func(password string) (bool, string){
				func(password string) (b bool, s string) {
					if len(password) > 10 {
						return false, "Password length is more than 10"
					}
					return true, ""
				},
			},
		},
	}

	for i := range data {
		t.Logf("\ttesting Data: %v ", data[i].signinData)
		{
			db := datastores.SqliteConnection("test.db")

			mailBox := NewSigninUserNanos(
				1,
				1000,
				db,
				data[i].firstFieldValidationRules,
				data[i].passwordValidationRules,

			)

			var resTo = make(chan nanos.Message)
			var errTo = make(chan error)
			content, err := json.Marshal(data[i].signinData)
			if err != nil {
				t.Fatal(err)
			}

			mailBox <- nanos.Message{
				Content: content,
				ResTo:   resTo,
				ErrTo:   errTo,
			}

			select {
			case _ = <-resTo:
				t.Errorf("\t\t%s\t %s", failure, "Nanos should not return response")
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
