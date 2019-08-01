package signinUser

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/bashar-saleh/auth-nanos/entities"
	"github.com/bashar-saleh/gonanos/nanos"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func NewSigninUserNanos(
	workersMaxCount int,
	taskQueueCapacity int,
	db *sql.DB,
	firstFieldValidationRules []func(firstField string) (bool, string),
	passwordValidationRules []func(password string) (bool, string),
) chan nanos.Message {

	myNanos := nanos.Nanos{
		Worker: &signinUserWorker{
			db:                        db,
			firstFieldValidationRules: firstFieldValidationRules,
			passwordValidationRules:   passwordValidationRules,
		},
		TaskQueueCapacity: taskQueueCapacity,
		WorkersMaxCount:   workersMaxCount,
	}

	return myNanos.TasksChannel()

}

type signinUserWorker struct {
	db                        *sql.DB
	firstFieldValidationRules []func(firstField string) (bool, string)
	passwordValidationRules   []func(password string) (bool, string)
}

func (w *signinUserWorker) Work(msg nanos.Message) {

	// extract content from msg
	var content struct {
		FirstField string
		Password   string
	}
	err := json.Unmarshal(msg.Content, &content)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// validate FirstField
	for i := range w.firstFieldValidationRules {
		isValid, errString := w.firstFieldValidationRules[i](content.FirstField)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(errString):
				return
			default:
				return
			}
		}
	}

	// validate Password
	for i := range w.passwordValidationRules {
		isValid, errString := w.passwordValidationRules[i](content.Password)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(errString):
				return
			default:
				return
			}
		}
	}

	// check if the first field exist in the db
	rows, err := w.db.Query("SELECT  name, username, email, phone, password, roles FROM users WHERE (username == ?) OR (email == ?) OR (phone == ?)", content.FirstField, content.FirstField, content.FirstField)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}
	defer rows.Close()
	if !rows.Next() {
		select {
		case msg.ErrTo <- errors.New("username or password is wrong"):
			return
		default:
			return
		}
	}
	var name string
	var username string
	var email string
	var phone string
	var hashedPassword string
	var rawRoles string
	err = rows.Scan(&name, &username, &email, &phone, &hashedPassword, &rawRoles)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// check password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(content.Password))
	if err != nil {
		select {
		case msg.ErrTo <- errors.New("username or password is wrong"):
			return
		default:
			return
		}
	}



	// return the correspond user
	var roles []string
	if rawRoles == "" {
		roles = nil
	}else {
	err = json.Unmarshal([]byte(rawRoles), &roles)
		if err != nil {
			select {
			case msg.ErrTo <- err:
				return
			default:
				return
			}
		}
	}

	user := entities.User{
		Name:     name,
		Username: username,
		Email:    email,
		Phone:    phone,
		Roles:    roles,
	}
	log.Println(user)

	rawUser, err := user.ToByte()
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	select {
	case msg.ResTo <- nanos.Message{Content: rawUser}:
		return
	default:
		return
	}

}
