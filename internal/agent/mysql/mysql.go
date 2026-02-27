package mysql

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) execSQL(query string) (string, error) {
	// The agent runs as vpspanel-agent, which has sudo access to everything.
	// We run `sudo mysql -e "query"`
	cmd := exec.Command("sudo", "mysql", "-e", query)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("mysql error: %v, output: %s", err, out.String())
	}
	return out.String(), nil
}

type Database struct {
	Name string `json:"name"`
}

type User struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

func (m *Manager) ListDatabases() ([]Database, error) {
	out, err := m.execSQL("SHOW DATABASES;")
	if err != nil {
		return nil, err
	}
	var dbs []Database
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // skip header "Database" and empty lines
		}
		name := strings.TrimSpace(line)
		// Skip default system databases
		if name == "information_schema" || name == "mysql" || name == "performance_schema" || name == "sys" {
			continue
		}
		dbs = append(dbs, Database{Name: name})
	}
	return dbs, nil
}

func (m *Manager) ListUsers() ([]User, error) {
	out, err := m.execSQL("SELECT User, Host FROM mysql.user;")
	if err != nil {
		return nil, err
	}
	var users []User
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // skip header
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			name := parts[0]
			// Skip system users
			if name == "root" || name == "mariadb.sys" || name == "mysql" {
				continue
			}
			users = append(users, User{Name: name, Host: parts[1]})
		}
	}
	return users, nil
}

func (m *Manager) CreateDatabase(name string) error {
	// Basic sanitization
	name = strings.ReplaceAll(name, "`", "")
	name = strings.ReplaceAll(name, ";", "")
	_, err := m.execSQL(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`;", name))
	return err
}

func (m *Manager) DeleteDatabase(name string) error {
	name = strings.ReplaceAll(name, "`", "")
	name = strings.ReplaceAll(name, ";", "")
	_, err := m.execSQL(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", name))
	return err
}

func (m *Manager) CreateUser(name, password string) error {
	name = strings.ReplaceAll(name, "'", "")
	password = strings.ReplaceAll(password, "'", "")
	_, err := m.execSQL(fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';", name, password))
	return err
}

func (m *Manager) DeleteUser(name string) error {
	name = strings.ReplaceAll(name, "'", "")
	_, err := m.execSQL(fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost';", name))
	return err
}

func (m *Manager) GrantPrivileges(dbName, userName string) error {
	dbName = strings.ReplaceAll(dbName, "`", "")
	userName = strings.ReplaceAll(userName, "'", "")

	// Ensure user exists and DB exists
	_, err := m.execSQL(fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", dbName, userName))
	if err != nil {
		return err
	}
	_, err = m.execSQL("FLUSH PRIVILEGES;")
	return err
}
