package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

type ShellType = string

const (
	shellTypePowershell ShellType = "powershell"
	shellTypeBash       ShellType = "bash"
	shellTypeBasic      ShellType = "basic"
	shellTypeInfer      ShellType = "infer"
)

func getShellType() ShellType {
	pid := os.Getppid()
	parentProc, _ := ps.FindProcess(pid)
	name := strings.ToLower(parentProc.Executable())

	if strings.Contains(name, "bash") || strings.Contains(name, "zsh") || strings.Contains(name, "ash") {
		return shellTypeBash
	}

	if strings.Contains(name, "powershell") || strings.Contains(name, "pwsh") {
		return shellTypePowershell
	}

	if runtime.GOOS == "windows" {
		return shellTypeBasic
	}

	return shellTypeBash
}

type CloudCredentials struct {
	AccountID       string `json:"AccountId"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func LoadAWSCredentialsFromEnvironment() CloudCredentials {
	return CloudCredentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		AccountID:       os.Getenv("AWSKEY_ACCOUNT"),
		Expiration:      os.Getenv("AWSKEY_EXPIRATION"),
	}
}

func (c *CloudCredentials) ValidUntil(account *Account, dur time.Duration) bool {
	if account == nil || c == nil {
		return false
	}

	if c.AccountID != account.ID {
		return false
	}

	expiration, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil {
		return false
	}

	return expiration.After(time.Now().Add(dur))
}

const (
	awsShellTypePowershell = `$Env:AWS_ACCESS_KEY_ID = "%v"
$Env:AWS_SECRET_ACCESS_KEY = "%v"
$Env:AWS_SESSION_TOKEN = "%v"
$Env:AWS_SECURITY_TOKEN = "%v"
$Env:TF_VAR_access_key = $Env:AWS_ACCESS_KEY_ID
$Env:TF_VAR_secret_key = $Env:AWS_SECRET_ACCESS_KEY
$Env:TF_VAR_token = $Env:AWS_SESSION_TOKEN
$Env:AWSKEY_EXPIRATION = "%v"
$Env:AWSKEY_ACCOUNT = "%v"
`
	awsShellTypeBasic = `SET AWS_ACCESS_KEY_ID=%v
SET AWS_SECRET_ACCESS_KEY=%v
SET AWS_SESSION_TOKEN=%v
SET AWS_SECURITY_TOKEN=%v
SET TF_VAR_access_key=%%AWS_ACCESS_KEY_ID%%
SET TF_VAR_secret_key=%%AWS_SECRET_ACCESS_KEY%%
SET TF_VAR_token=%%AWS_SESSION_TOKEN%%
SET AWSKEY_EXPIRATION=%v
SET AWSKEY_ACCOUNT=%v
`
	awsShellTypeBash = `export AWS_ACCESS_KEY_ID=%v
export AWS_SECRET_ACCESS_KEY=%v
export AWS_SESSION_TOKEN=%v
export AWS_SECURITY_TOKEN=%v
export TF_VAR_access_key=$AWS_ACCESS_KEY_ID
export TF_VAR_secret_key=$AWS_SECRET_ACCESS_KEY
export TF_VAR_token=$AWS_SESSION_TOKEN
export AWSKEY_EXPIRATION=%v
export AWSKEY_ACCOUNT=%v
`
)

func (c CloudCredentials) WriteFormat(w io.Writer, format ShellType) (int, error) {
	var str string
	if format == shellTypeInfer {
		format = getShellType()
	}

	switch format {
	case shellTypePowershell:
		str = awsShellTypePowershell
	case shellTypeBasic:
		str = awsShellTypeBasic
	case shellTypeBash:
		str = awsShellTypeBash
	}

	return fmt.Fprintf(w, str, c.AccessKeyID, c.SecretAccessKey, c.SessionToken, c.SessionToken, c.Expiration, c.AccountID)
}
