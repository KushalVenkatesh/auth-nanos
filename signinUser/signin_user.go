package signinUser

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/bashar-saleh/gonanos/nanos"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func NewSigninUserNanos(
	workersMaxCount int,
	taskQueueCapacity int,
	db *sql.DB,
	key string,
	hours int,
	firstFieldValidationRules []func(firstField string) (bool, string),
	passwordValidationRules []func(password string) (bool, string),
) chan nanos.Message {

	myNanos := nanos.Nanos{
		Worker: &signinUserWorker{
			db:                        db,
			key:                       key,
			hours:                     hours,
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
	key                       string
	hours                     int
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
	rows, err := w.db.Query("SELECT  id, name, username, email, phone, password, roles FROM users WHERE (username == ?) OR (email == ?) OR (phone == ?)", content.FirstField, content.FirstField, content.FirstField)
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
	var id int
	var name string
	var username string
	var email string
	var phone string
	var hashedPassword string
	var rawRoles string
	err = rows.Scan(&id, &name, &username, &email, &phone, &hashedPassword, &rawRoles)
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

	// return jwt token
	var roles []string
	if rawRoles == "" {
		roles = nil
	} else {
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
	token, err := w.createToken(id, roles)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	select {
	case msg.ResTo <- nanos.Message{Content: []byte(token)}:
		return
	default:
		return
	}

}

func (w *signinUserWorker) createToken(ID int, roles []string) (string, error) {
	jwtKey := []byte(w.key)
	exp := time.Now().Add(time.Duration(w.hours) * time.Hour)

	claims := claims{
		ID:    ID,
		Roles: roles,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

type claims struct {
	ID    int   `json:"id"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}
