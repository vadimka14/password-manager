package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type Password struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	Category     string `json:"category"`
	CreatedAt    time.Time
	LastModified time.Time
}

func NewPassword(name, value, category string) Password {

	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func main() {
	password := NewPassword("anten41k", "39f93fffj9dfd", "kaba4ki")
	data, err := json.Marshal(password)
	if err != nil {
		fmt.Errorf("encode password: %w", err)
	}
	fmt.Println(string(data))

}
