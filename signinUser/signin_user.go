package signinUser

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/bashar-saleh/gonanos/nanos"
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
	for i := range w.passwordValidationRules 	{
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

}
