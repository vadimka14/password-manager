package main

import (
	"errors"
	"fmt"
	"log"
	"time"
)

var ErrNotInitialized = errors.New("password manager not initialized")
var ErrPasswordExists = errors.New("password already exists")

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"createdat"`
	LastModified time.Time `json:"lastmodified"`
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

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPasswordManager(filepath string) *PasswordManager {
	passwords := make(map[string]Password)
	return &PasswordManager{
		passwords:     passwords,
		masterKey:     nil,
		filePath:      filepath,
		isInitialized: false,
	}
}

func main() {

	passwordManager := NewPasswordManager("test.json")
	err := passwordManager.SetMasterPassword("weak343443")
	if err != nil {
		log.Fatalf("Weak master password: %v", err)
	}
	fmt.Printf("Strong master password: %v\nManager initialized: %v\nMaster key length: %d\n", err, passwordManager.isInitialized, len(passwordManager.masterKey))

	err = passwordManager.SavePassword("anten41k", "39f93fffj9dfd", "kaba4ki")
	if err != nil {
		if errors.Is(err, ErrNotInitialized) {
			fmt.Printf("Save to uninitialized manager: %v", err)
		}
		if errors.Is(err, ErrPasswordExists) {
			fmt.Printf("Duplicate save result: %v", err)
		}
	}
	fmt.Printf("First save result: %v", err)
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return fmt.Errorf("password is too weak")
	}
	masterKey := make([]byte, 32)
	copy(masterKey, []byte(masterPassword))
	pm.masterKey = masterKey
	pm.isInitialized = true
	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}
	_, ok := pm.passwords[name]
	if ok {
		return ErrPasswordExists
	}
	password := NewPassword(name, value, category)
	pm.passwords[name] = password

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New("password manager not initialized")
	}

	_, ok := pm.passwords[name]
	if !ok {
		return Password{}, errors.New("password not found")
	}

	return pm.passwords[name], nil
}
