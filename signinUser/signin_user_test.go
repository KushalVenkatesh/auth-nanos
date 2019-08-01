package signinUser

import (
	"encoding/json"
	"github.com/bashar-saleh/auth-nanos/datastores"
	"github.com/bashar-saleh/auth-nanos/entities"
	"github.com/bashar-saleh/gonanos/nanos"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"regexp"
	"testing"
	"time"
)

var succeed = "\u2713"
var failure = "\u2717"

func TestSigninUser(t *testing.T) {
	t.Run("testValidationRules", testValidationRules)
	t.Run("Given username not exist in DB When we signin Then error is returned with msg //username or password is wrong//", signinNonExistUser)
	t.Run("Given password is wrong When we signin Then error is returned with msg //username or password is wrong//", signinWrongPassword)
	t.Run("Given username and password are correct When we signin Then jwt token is returned ", signinValidData)
}

func signinValidData(t *testing.T) {
	createUserInDB(entities.User{
		Name:     "Bashar",
		Username: "bashar_123",
		Password: "bb123123",
		Roles:    []string{"admin", "user"},
	})
	mailBox := NewSigninUserNanos(1, 2, datastores.SqliteConnection("test.db"), "secretKey", 4, nil, nil)
	var resTo = make(chan nanos.Message)
	var errTo = make(chan error)

	var content = struct {
		FirstField string
		Password   string
	}{
		FirstField: "bashar_123",
		Password:   "bb123123",
	}
	rawContent, _ := json.Marshal(content)
	mailBox <- nanos.Message{
		Content: rawContent,
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	select {
	case res := <-resTo:
		token := string(res.Content)
		claims := claims{}
		tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("secretKey"), nil
		})
		if err != nil {
			t.Fatalf("\t%s\tError was happened when extracting user from message -- %s", failure, err.Error())
		}
		if !tkn.Valid {
			t.Fatalf("\t%s\tToken is Invalid", failure)
		}

		if (claims.ID == 1) && (len(claims.Roles) == 2) {
			t.Logf("\t%s\t Pass", succeed)
			return
		}

		t.Errorf("\t%s\tthe returned token is not correct -- %v", failure, claims)
	case err := <-errTo:
		t.Errorf("\t%s\t Nanos should not return any error -- %s", failure, err.Error())
	case <-time.After(time.Second * 10):
		t.Errorf("\t%s\terror timeout", failure)

	}
}

func signinWrongPassword(t *testing.T) {

	createUserInDB(entities.User{
		Name:     "Bashar",
		Username: "bashar_123",
		Password: "!@#!!@#",
	})
	mailBox := NewSigninUserNanos(1, 2, datastores.SqliteConnection("test.db"), "secretKey", 4, nil, nil)
	var resTo = make(chan nanos.Message)
	var errTo = make(chan error)

	var content = struct {
		FirstField string
		Password   string
	}{
		FirstField: "bashar_123",
		Password:   "123123",
	}
	rawContent, _ := json.Marshal(content)
	mailBox <- nanos.Message{
		Content: rawContent,
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	select {
	case _ = <-resTo:
		t.Errorf("\t%s\tNanos shloud not return response", failure)
	case err := <-errTo:
		matched, _ := regexp.MatchString("username or password is wrong", err.Error())
		if !matched {
			t.Fatalf("\t%s\terror message is not what supposed to be --  %s", failure, err.Error())

		}
		t.Logf("\t%s\t Pass", succeed)
	case <-time.After(time.Second * 10):
		t.Errorf("\t%s\terror timeout", failure)

	}
}

func signinNonExistUser(t *testing.T) {
	createUserInDB(entities.User{
		Name:     "Bashar",
		Username: "bashar_!@#",
		Password: "123",
	})
	mailBox := NewSigninUserNanos(1, 2, datastores.SqliteConnection("test.db"), "secretKey", 4, nil, nil)

	var resTo = make(chan nanos.Message)
	var errTo = make(chan error)
	var content = struct {
		FirstField string
		Password   string
	}{
		FirstField: "bashar_123",
		Password:   "qweqwe",
	}
	rawContent, _ := json.Marshal(content)

	mailBox <- nanos.Message{
		Content: rawContent,
		ResTo:   resTo,
		ErrTo:   errTo,
	}

	select {
	case _ = <-resTo:
		t.Fatalf("\t%s\tNanos shloud not return response", failure)
	case err := <-errTo:
		matched, _ := regexp.MatchString("username or password is wrong", err.Error())
		if !matched {
			t.Errorf("\t%s\terror message is not what supposed to be --  %s", failure, err.Error())
		}
		t.Logf("\t%s\t Pass", succeed)
	case <-time.After(time.Second * 10):
		t.Errorf("\t%s\terror timeout", failure)

	}

}

func createUserInDB(user entities.User) {
	db := datastores.SqliteConnection("test.db")

	// check if table exists
	rows, err := db.Query("select name from sqlite_master where name='users' and type='table'")
	if err != nil {
		log.Fatal(err)
	}
	if !rows.Next() {
		// create users table
		stmt := `
			create table  users (
			    	id integer not null primary key autoincrement, 
			    	name text,
			    	username text,
			    	password varchar(250),
			    	email text,
			    	phone text,
			    	roles text
			                    );
			delete from users;`
		_, err = db.Exec(stmt)
		if err != nil {
			log.Fatal(err)
		}
	}
	rows.Close()

	// inserting user record
	tx, _ := db.Begin()
	stm, err := tx.Prepare("insert into users (name, username, email, phone, password, roles) values (?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stm.Close()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	roles, err := json.Marshal(user.Roles)
	if err != nil {
		log.Fatal(err)
	}
	_, err = stm.Exec(user.Name, user.Username, user.Email, user.Phone, hashedPassword, roles)
	if err != nil {
		log.Fatal(err.Error())
	}
	err = tx.Commit()
	if err != nil {
		log.Fatal(err.Error())
	}
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
				"secretKey",
				5,
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
