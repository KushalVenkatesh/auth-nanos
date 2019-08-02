package validateJWT

import (
	"encoding/json"
	"errors"
	"github.com/bashar-saleh/gonanos/nanos"
	"github.com/dgrijalva/jwt-go"
)

func NewValidateJWTNanos(
	workersMaxCount int,
	taskQueueCapacity int,
	key string,
) chan nanos.Message {

	worker := validateJWTWorker{
		key: key,
	}

	myNanos := nanos.Nanos{
		Worker:            &worker,
		WorkersMaxCount:   workersMaxCount,
		TaskQueueCapacity: taskQueueCapacity,
	}
	return myNanos.TasksChannel()

}

type validateJWTWorker struct {
	key string
}

func (w *validateJWTWorker) Work(msg nanos.Message) {

	// extract token from msg
	if msg.Content == nil {
		select {
		case msg.ErrTo <- errors.New("msg is null"):
			return
		default:
			return
		}
	}
	token := string(msg.Content)

	// extract claims from token
	var claims Claims
	err := w.claimsFromToken(token, &claims)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		select {
		case msg.ErrTo <- err:
			return
		default:
			return
		}
	}

	// sending the response back
	select {
	case msg.ResTo <- nanos.Message{Content: rawClaims}:
		return
	default:
		return
	}

}

func (w *validateJWTWorker) claimsFromToken(token string, claims *Claims) error {

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(w.key), nil
	})
	if err != nil {
		return err
	}
	if !tkn.Valid {
		return errors.New("token is not valid")
	}
	return nil
}

type Claims struct {
	ID    int      `json:"id"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}
