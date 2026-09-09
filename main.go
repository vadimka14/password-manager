package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
	clear       = "\033[H\033[2J"
)

var ErrNotInitialized = errors.New("password manager not initialized")
var ErrPasswordExists = errors.New("password already exists")
var ErrPasswordNotFound = errors.New("password not found")
var ErrWeakPassword = errors.New("password is too weak")
var ErrToJson = errors.New("Failed to serialize the store to JSON")
var ErrFromJson = errors.New("Failed to serialize the store from JSON")

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
	ShowMainMenu()
	// PrintPasswordList()

	pm := NewPasswordManager("test.json")
	// if err := HandlePasswordGeneration(pm); err != nil {
	// 	log.Println(err)
	// }

	// waitForEnter()

	if err := HandlePasswordAdd(pm); err != nil {
		log.Println(err)
	}

	waitForEnter()

	if err := HandlePasswordSearch(pm); err != nil {
		log.Println(err)
	}

	waitForEnter()

	if err := HandlePasswordUpdate(pm); err != nil {
		log.Println(err)
	}

	waitForEnter()

	// err := pm.SetMasterPassword("weak343443")
	// if err != nil {
	// 	log.Fatalf("Weak master password: %v", err)
	// }
	// fmt.Printf("Strong master password: %v\nManager initialized: %v\nMaster key length: %d\n", err, pm.isInitialized, len(pm.masterKey))

	// err = pm.SavePassword("anten41k", "39f93fffj9dfd", "kaba4ki")
	// if err != nil {
	// 	if errors.Is(err, ErrNotInitialized) {
	// 		fmt.Printf("Save to uninitialized manager: %v", err)
	// 	}
	// 	if errors.Is(err, ErrPasswordExists) {
	// 		fmt.Printf("Duplicate save result: %v", err)
	// 	}
	// }
	// fmt.Printf("First save result: %v", err)

	// // password, err := passwordManager.GetPassword("anten41k")
	// // if err != nil {
	// // 	if errors.Is(err, ErrNotInitialized) {
	// // 		fmt.Printf("Get from uninitialized manager: %v", err)
	// // 	}
	// // 	if errors.Is(err, ErrPasswordNotFound) {
	// // 		fmt.Printf("Get non-existent password: %v", err)
	// // 	}
	// // }
	// // fmt.Printf("Found password: %v\n", password)

	// // listPasswords := passwordManager.ListPasswords()
	// // fmt.Printf("Total passwords: %d\n", len(listPasswords))
	// // for _, password := range listPasswords {
	// // 	fmt.Printf("Service: %s      Category: %s\n", password.Name, password.Category)
	// // }
	// generatedPassword, err := pm.GeneratePassword(12)
	// if err != nil {
	// 	if errors.Is(err, ErrWeakPassword) {
	// 		fmt.Printf("Error for short password: %v", err)
	// 	}
	// 	fmt.Println(err)
	// }
	// fmt.Printf("Generated password: %s\n", generatedPassword)

	// err = pm.SaveToFile()
	// if err != nil {
	// 	if errors.Is(err, ErrNotInitialized) {
	// 		fmt.Printf("Save without init: %v\n", err)
	// 	} else if errors.Is(err, ErrToJson) {
	// 		fmt.Printf("serialization error: %v", err)
	// 	} else {
	// 		fmt.Printf("encryption error: %v", err)
	// 	}
	// }
	// fmt.Printf("Save after init: %v\n", err)

	// err = pm.LoadFromFile()
	// if err != nil {
	// 	fmt.Println(err)
	// }

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
		return "", ErrWeakPassword
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
		return ErrToJson
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

func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(file, nonce); err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	err = json.Unmarshal(decryptedData, &pm.passwords)
	if err != nil {
		return ErrFromJson
	}

	return nil
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	var specials = "!@#$%^&*"
	if len(password) < 8 {
		return ErrWeakPassword
	}
	isCapital := false
	isNumber := false
	isSpecial := false
	isLower := false

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			isCapital = true
		case unicode.IsLower(r):
			isLower = true
		case unicode.IsDigit(r):
			isNumber = true
		case strings.ContainsRune(specials, r):
			isSpecial = true
		}
	}
	if isCapital && isLower && isNumber && isSpecial {
		return nil
	}
	return ErrWeakPassword
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	passwordsByCategory := make([]Password, 0, len(pm.passwords))

	for _, p := range pm.passwords {
		if strings.EqualFold(p.Category, category) {
			passwordsByCategory = append(passwordsByCategory, p)
		}
	}
	return passwordsByCategory
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	duplicates := make(map[string][]string, len(pm.passwords))

	for _, p := range pm.passwords {
		duplicates[p.Value] = append(duplicates[p.Value], p.Name)
	}

	for value, names := range duplicates {
		if len(names) <= 1 {
			delete(duplicates, value)
		}
	}

	return duplicates
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}

	if _, ok := pm.passwords[name]; !ok {
		return fmt.Errorf("Updating a nonexistent password: %w", ErrPasswordNotFound)
	}

	if err := pm.CheckPasswordStrength(newValue); err != nil {
		return fmt.Errorf("Updating to a weak password: %w", err)
	}
	entry := pm.passwords[name]
	entry.Value = newValue
	entry.LastModified = time.Now()

	pm.passwords[name] = entry

	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return ErrNotInitialized
	}
	_, ok := pm.passwords[name]
	if !ok {
		return ErrPasswordNotFound
	}

	delete(pm.passwords, name)
	/// для перевірки чи точно видалився
	_, ok = pm.passwords[name]
	if !ok {
		return ErrPasswordNotFound
	}

	return nil
}

func (pm *PasswordManager) ListCategories() []string {
	categories := make(map[string]struct{})
	for _, p := range pm.passwords {
		categories[p.Category] = struct{}{}
	}
	listOfCategories := make([]string, 0, len(categories))
	for category := range categories {
		listOfCategories = append(listOfCategories, category)
	}

	sort.Strings(listOfCategories)

	return listOfCategories
}

func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["total"] = len(pm.passwords)

	categories := make(map[string]int)
	for _, v := range pm.ListCategories() {
		categories[v] = len(pm.GetPasswordsByCategory(v))
	}

	stats["categories"] = categories

	var oldestDate, newestDate time.Time

	if len(pm.passwords) == 0 {
		stats["oldest"] = oldestDate
		stats["newest"] = newestDate
	} else {
		isFirst := true
		for _, password := range pm.passwords {
			if isFirst {
				isFirst = false
				oldestDate = password.CreatedAt
				newestDate = password.CreatedAt
				continue
			}
			if password.CreatedAt.Before(oldestDate) {
				oldestDate = password.CreatedAt
			}
			if password.CreatedAt.After(newestDate) {
				newestDate = password.CreatedAt
			}
		}
		stats["oldest"] = oldestDate
		stats["newest"] = newestDate
	}

	return stats
}

func clearScreen() {
	fmt.Print(clear)
}
func showSuccess(message string) {
	fmt.Printf("%s✓ Success: %s%s\n", colorGreen, message, colorReset)
}
func showError(message string) {
	fmt.Printf("%s✗ Error: %s%s\n", colorRed, message, colorReset)
}
func showInfo(message string) {
	fmt.Printf("%s→ Info: %s%s\n", colorYellow, message, colorReset)
}
func waitForEnter() {
	fmt.Print("Press Enter to continue...")
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, "input error:", err)
		return
	}

}

func ReadUserInput(prompt string) string {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("%s: ", prompt)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "input error: ", err)
		}
		return ""
	}
	return strings.TrimSpace(scanner.Text())

}

func readPassword(prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()

	return string(password), nil
}

func ShowMainMenu() {
	clearScreen()
	fmt.Println(strings.Repeat("=", 42))
	fmt.Println(strings.Repeat(" ", 12), "Password Manager")
	fmt.Println(strings.Repeat("=", 42))
	fmt.Println(`1. Generate new password
2. Add new password
3. Get password
4. List all passwords
5. Update password
6. Delete password
7. List categories
8. Show password statistics
9. Find duplicate passwords
0. Exit`)
	fmt.Println(strings.Repeat("=", 42))
}

func PrintPasswordList(passwords []Password) {
	fmt.Println("=== Password list ===")
	fmt.Printf("%-17s %-15s %-20s %-20s\n", "Name", "Category", "Created", "Last Modified")
	fmt.Println(strings.Repeat("-", 80))
	for _, password := range passwords {
		fmt.Printf("%-17s %-15s %-20s %-20s\n", password.Name, password.Category, password.CreatedAt.Format("2006-01-02"), password.LastModified.Format("2006-01-02"))
	}
}

func ShowPasswordDetails(password Password) {
	fmt.Printf("=== Password details ===\n")
	fmt.Printf("Service: %s\nCategory: %s\nPassword: %s\nCreated: %s\nLast Modified: %s\n", password.Name, password.Category, password.Value, password.CreatedAt.Format("2006-01-02 15:04:05"), password.LastModified.Format("2006-01-02 15:04:05"))
}

func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Password Generation ===")
	strLength := ReadUserInput("Enter password length (min 8)")
	length, err := strconv.Atoi(strLength)
	if err != nil {
		fmt.Println()
		showError(err.Error())
		return err
	}
	password, err := pm.GeneratePassword(length)
	if err != nil {
		showError(err.Error())
		return err
	}

	showSuccess("Password generated successfully")
	fmt.Printf("Generated password: %s\n", password)

	return nil
}

func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	serviceName := ReadUserInput("Enter service name")
	password, err := readPassword("Enter password (or press Enter to generate)")
	if err != nil {
		showError(err.Error())
		return err
	}
	if len(password) == 0 {
		strLength := ReadUserInput("Enter password length (min 8)")
		length, err := strconv.Atoi(strLength)
		if err != nil {
			fmt.Println()
			showError(err.Error())
			return err
		}
		password, err = pm.GeneratePassword(length)
		if err != nil {
			showError(err.Error())
			return err
		}
		showInfo(fmt.Sprintf("Generated password: %s", password))
	}

	category := ReadUserInput("Enter category")
	err = pm.SavePassword(serviceName, password, category)
	if err != nil {
		showError(err.Error())
		return err
	}
	showSuccess("Password saved successfully")
	return nil
}
func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Search Password ===")
	serviceName := ReadUserInput("Enter service name")
	password, err := pm.GetPassword(serviceName)
	if err != nil {
		showError(err.Error())
		return err
	}
	fmt.Printf("Password Details:\nService: %s\nCategory: %s\nPassword: %s\nCreated: %s\nLast Modified: %s\n", password.Name, password.Category, password.Value, password.CreatedAt.Format("2006-01-02 15:04:05"), password.LastModified.Format("2006-01-02 15:04:05"))
	return nil
}

func HandlePasswordUpdate(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Update Password ===")
	serviceName := ReadUserInput("Enter service name")
	password, err := readPassword(fmt.Sprintf("Enter the new password for %s", serviceName))
	if err != nil {
		showError(err.Error())
		return err
	}
	if err := pm.UpdatePassword(serviceName, password); err != nil {
		showError(err.Error())
		return err
	}

	showSuccess(fmt.Sprintf("Password for %s updated successfully", serviceName))

	return nil
}
