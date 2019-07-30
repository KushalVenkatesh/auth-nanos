package registerUser

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/bashar-saleh/auth-nanos/entities"
	"github.com/bashar-saleh/gonanos/nanos"
	"log"
)

func NewRegisterUserNanos(
	workersMaxCount int,
	taskQueueCapacity int,
	db *sql.DB,
	nameValidationRules []func(name string) (bool, string),
	usernameValidationRules []func(username string) (bool, string),
	passwordValidationRules []func(password string) (bool, string),
	emailValidationRules []func(email string) (bool, string),
	phoneValidationRules []func(phone string) (bool, string),

) chan nanos.Message {

	worker := &registerUserWorker{
		db:                      db,
		nameValidationRules:     nameValidationRules,
		emailValidationRules:    emailValidationRules,
		passwordValidationRules: passwordValidationRules,
		phoneValidationRules:    phoneValidationRules,
		usernameValidationRules: usernameValidationRules,
	}

	worker.prepareStore()

	myNanos := nanos.Nanos{
		WorkersMaxCount:   workersMaxCount,
		TaskQueueCapacity: taskQueueCapacity,
		Worker:            worker,
	}

	return myNanos.TasksChannel()

}

type registerUserWorker struct {
	db                      *sql.DB
	nameValidationRules     []func(name string) (bool, string)
	usernameValidationRules []func(username string) (bool, string)
	passwordValidationRules []func(password string) (bool, string)
	emailValidationRules    []func(email string) (bool, string)
	phoneValidationRules    []func(phone string) (bool, string)
}

func (w *registerUserWorker) Work(msg nanos.Message) {

	// extract content from message
	userData, err := entities.UserFromBytes(msg.Content)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// validate name
	for i := range w.nameValidationRules {
		isValid, nonValidMsg := w.nameValidationRules[i](userData.Name)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(nonValidMsg):
				return
			default:
				return
			}
		}
	}

	// validate username
	for i := range w.usernameValidationRules {
		isValid, nonValidMsg := w.usernameValidationRules[i](userData.Username)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(nonValidMsg):
				return
			default:
				return
			}
		}
	}

	// validate password
	for i := range w.passwordValidationRules {
		isValid, nonValidMsg := w.passwordValidationRules[i](userData.Password)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(nonValidMsg):
				return
			default:
				return
			}
		}
	}

	// validate email
	for i := range w.emailValidationRules {
		isValid, nonValidMsg := w.emailValidationRules[i](userData.Email)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(nonValidMsg):
				return
			default:
				return
			}
		}
	}

	// validate phone
	for i := range w.phoneValidationRules {
		isValid, nonValidMsg := w.phoneValidationRules[i](userData.Phone)
		if !isValid {
			select {
			case msg.ErrTo <- errors.New(nonValidMsg):
				return
			default:
				return
			}
		}
	}

	// check if the username or email or phone exist before
	q := "SELECT username, email, phone FROM users WHERE "
	var qValus []interface{}

	if userData.Username != "" {
		q += "(username = ?) "
		qValus = append(qValus, userData.Username)
	} else {
		q += "(0 = 1) "
	}
	if userData.Email != "" {
		q += "OR (email = ?) "
		qValus = append(qValus, userData.Email)
	} else {
		q += "OR (1 = 0) "
	}
	if userData.Phone != "" {
		q += "OR (phone = ?) "
		qValus = append(qValus, userData.Phone)
	} else {
		q += "OR (1 = 0) "
	}

	rows, err := w.db.Query(q, qValus...)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var email string
		var phone string
		err := rows.Scan(&username, &email, &phone)
		if err != nil {
			select {
			case msg.ErrTo <- err:
				return
			default:
				return
			}
		}

		select {
		case msg.ErrTo <- errors.New("User with data: username=" + username + " email=" + email + " phone=" + phone + " is exist before"):
			return
		default:
			return
		}
	}

	// saving to db
	tx, err := w.db.Begin()
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// stringify roles
	var rolesString string
	if len(userData.Roles) == 0 || userData.Roles == nil {
		rolesString = ""
	} else {
		raw, err := json.Marshal(userData.Roles)
		if err != nil {
			select {
			case msg.ErrTo <- err:
				return
			default:
				return
			}
		}
		rolesString = string(raw)
	}

	stmt, err := tx.Prepare("insert into users (name, username, email, phone, roles) values (?, ?, ?, ?, ?)")
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}
	defer stmt.Close()

	result, err := stmt.Exec(userData.Name, userData.Username, userData.Email, userData.Phone, rolesString)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}
	id, err := result.LastInsertId()
	if err != nil {
		select {
		case msg.ErrTo <- err:
		default:
			return
		}
	}

	err = tx.Commit()
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// return response
	rawID := make([]byte, 8)
	binary.LittleEndian.PutUint64(rawID, uint64(id))

	if err != nil {
		select {
		case msg.ErrTo <- err:
		default:
			return
		}
	}
	select {
	case msg.ResTo <- nanos.Message{Content: rawID}:
		return
	default:
		return
	}

}

func (w *registerUserWorker) prepareStore() {

	// check if table exists
	rows, err := w.db.Query("select name from sqlite_master where name='users' and type='table'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		return
	}

	// create users table
	stmt := `
			create table  users (
			    	id integer not null primary key autoincrement, 
			    	name text,
			    	username text,
			    	password text,
			    	email text,
			    	phone text,
			    	roles text
			                    );
			delete from users;`
	_, err = w.db.Exec(stmt)
	if err != nil {
		log.Fatal(err)
	}

}
