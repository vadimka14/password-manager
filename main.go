package main

import (
	"fmt"
	"log"
	"time"
)

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
	// password := NewPassword("anten41k", "39f93fffj9dfd", "kaba4ki")
	// data, err := json.Marshal(password)
	// if err != nil {
	// 	fmt.Errorf("encode password: %w", err)
	// }
	// fmt.Println(string(data))
	passwordManager := NewPasswordManager("test.json")
	err := passwordManager.SetMasterPassword("weak343443")
	if err != nil {
		log.Fatalf("Weak master password: %v", err)
	}
	fmt.Printf("Strong master password: %v\nManager initialized: %v\nMaster key length: %d\n", err, passwordManager.isInitialized, len(passwordManager.masterKey))
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
		return fmt.Errorf("password manager not initialized")
	}
	_, ok := pm.passwords[name]
	if ok {
		return fmt.Errorf("password already exists")
	}
	password := NewPassword(name, value, category)
	pm.passwords[name] = password

	return nil
}
