package entities

import "encoding/json"

type User struct {
	Name string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email string `json:"email"`
	Phone string `json:"phone"`
	Roles []string `json:"roles"`
}

func(u User) ToByte() ([]byte, error){

	raw, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func UserFromBytes(raw []byte) (User, error) {
	var user User
	err := json.Unmarshal(raw, &user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}