package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var ErrNotInitialized = errors.New("password manager not initialized")
var ErrPasswordExists = errors.New("password already exists")
var ErrPasswordNotFound = errors.New("password not found")
var ErrShortPassword = errors.New("password is too weak")
var ErrJson = errors.New("Failed to serialize the store to JSON")

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

	pm := NewPasswordManager("test.json")
	err := pm.SetMasterPassword("weak343443")
	if err != nil {
		log.Fatalf("Weak master password: %v", err)
	}
	fmt.Printf("Strong master password: %v\nManager initialized: %v\nMaster key length: %d\n", err, pm.isInitialized, len(pm.masterKey))

	err = pm.SavePassword("anten41k", "39f93fffj9dfd", "kaba4ki")
	if err != nil {
		if errors.Is(err, ErrNotInitialized) {
			fmt.Printf("Save to uninitialized manager: %v", err)
		}
		if errors.Is(err, ErrPasswordExists) {
			fmt.Printf("Duplicate save result: %v", err)
		}
	}
	fmt.Printf("First save result: %v", err)

	// password, err := passwordManager.GetPassword("anten41k")
	// if err != nil {
	// 	if errors.Is(err, ErrNotInitialized) {
	// 		fmt.Printf("Get from uninitialized manager: %v", err)
	// 	}
	// 	if errors.Is(err, ErrPasswordNotFound) {
	// 		fmt.Printf("Get non-existent password: %v", err)
	// 	}
	// }
	// fmt.Printf("Found password: %v\n", password)

	// listPasswords := passwordManager.ListPasswords()
	// fmt.Printf("Total passwords: %d\n", len(listPasswords))
	// for _, password := range listPasswords {
	// 	fmt.Printf("Service: %s      Category: %s\n", password.Name, password.Category)
	// }
	generatedPassword, err := pm.GeneratePassword(12)
	if err != nil {
		if errors.Is(err, ErrShortPassword) {
			fmt.Printf("Error for short password: %v", err)
		}
		fmt.Println(err)
	}
	fmt.Printf("Generated password: %s\n", generatedPassword)

	err = pm.SaveToFile()
	if errors.Is(err, ErrNotInitialized) {
		fmt.Printf("Save without init: %v\n", err)
	} else if errors.Is(err, ErrJson) {
		fmt.Printf("serialization error: %v", err)
	} else {
		fmt.Printf("Save after init: %v\n", err)
	}

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
		return Password{}, ErrNotInitialized
	}

	password, ok := pm.passwords[name]
	if !ok {
		return Password{}, ErrPasswordNotFound
	}

	return password, nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	listPasswords := make([]Password, 0, len(pm.passwords))
	for _, value := range pm.passwords {
		listPasswords = append(listPasswords, value)
	}
	return listPasswords
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	if length < 8 {
		return "", ErrShortPassword
	}
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	for i := range buffer {
		buffer[i] = charset[int(buffer[i])%len(charset)]
	}

	return string(buffer), nil
}

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return ErrJson
	}
	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	cipherData := gcm.Seal(nil, nonce, data, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	cipherElements := append(nonce, cipherData...)

	if _, err = file.Write(cipherElements); err != nil {
		return err
	}

	return nil
}
