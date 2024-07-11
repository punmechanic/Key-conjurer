package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

var (
	FlagRegion        = "region"
	FlagRoleName      = "role"
	FlagTimeRemaining = "time-remaining"
	FlagTimeToLive    = "ttl"
	FlagBypassCache   = "bypass-cache"
	FlagLogin         = "login"
)

var (
	// outputTypeEnvironmentVariable indicates that keyconjurer will dump the credentials to stdout in Bash environment variable format
	outputTypeEnvironmentVariable = "env"
	// outputTypeAWSCredentialsFile indicates that keyconjurer will dump the credentials into the ~/.aws/credentials file.
	outputTypeAWSCredentialsFile = "awscli"
	permittedOutputTypes         = []string{outputTypeAWSCredentialsFile, outputTypeEnvironmentVariable}
	permittedShellTypes          = []string{shellTypePowershell, shellTypeBash, shellTypeBasic, shellTypeInfer}
)

type GetCommand struct {
	AccountName     string `arg:"" help:"The account name or alias"`
	Region          string `default:"us-west-2" env:"AWS_REGION" help:"The region to retrieve credentials in"`
	Role            string `name:"role" short:"r" help:"The name of the role to assume." optional:""`
	SessionName     string `name:"session-name" help:"The name of the role session name that will show up in CloudTrail logs" default:"KeyConjurer-AssumeRole"`
	Output          string `short:"o" name:"output" enum:"awscli,file,env" default:"env" help:"Specifies how to output credentials. Env outputs to Environment Variables according to the cloud type; awscli and file all deposit to an ini-style file"`
	Shell           string `name:"shell" default:"infer" help:"If output type is env, determines which format to output credentials in - by default, the format is inferred based on the execution environment. WSL users may wish to overwrite this to bash"`
	OutputDirectory string `name:"directory" optional:"" help:"If output is set to awscli or file, the directory to deposit the credentials into"`
	BypassCache     bool   `name:"bypass-cache" default:"false" help:"Do not check the cache for accounts and send the application ID as-is to Okta. This is useful if you have an ID you know is an Okta application ID and it is not stored in your local account cache"`
	Login           bool   `name:"login" default:"false" help:"Login to Okta before running the command"`
	Cloud           string `enum:"aws,tencent" default:"aws" help:"The cloud you are generating credentials for"`
	TimeToLive      int    `name:"ttl" default:"1" help:"The key timeout in hours from 1 to 8"`
	TimeRemaining   int    `name:"time-remaining" default:"60" help:"Request new keys if there are no keys in the environment or the current keys expire within <time-remaining> minutes."`
}

func isMemberOfSlice(slice []string, val string) bool {
	for _, member := range slice {
		if member == val {
			return true
		}
	}

	return false
}

func resolveApplicationInfo(cfg *Config, bypassCache bool, nameOrID string) (*Account, bool) {
	if bypassCache {
		return &Account{ID: nameOrID, Name: nameOrID}, true
	}
	return cfg.FindAccount(nameOrID)
}

func (GetCommand) Help() string {
	return `A role must be specified when using this command through the --role flag. You may list the roles you can assume through the roles command.`
}

var ErrNoRoleFlag = errors.New("no role flag specified")

func (g GetCommand) Run(appCtx *AppContext) error {
	ctx := context.Background()
	if HasTokenExpired(appCtx.Config.Tokens) {
		// TODO: Re-implement
		return ErrTokensExpiredOrAbsent
		// if ok, _ := cmd.Flags().GetBool(FlagLogin); ok {
		// 	// urlOnly, _ := cmd.Flags().GetBool(FlagURLOnly)
		// 	// noBrowser, _ := cmd.Flags().GetBool(FlagNoBrowser)
		// 	login := LoginCommand{
		// 		OIDCDomain: oidcDomain,
		// 		ClientID:   clientID,
		// 		Output:     LoginOutputFriendly,
		// 	}

		// 	ctx := AppContext{
		// 		Config: config,
		// 	}

		// 	if err := login.Run(&ctx); err != nil {
		// 		return err
		// 	}
		// } else {
		// }
		// return nil
	}

	if !isMemberOfSlice(permittedOutputTypes, g.Output) {
		return ValueError{Value: g.Output, ValidValues: permittedOutputTypes}
	}

	if !isMemberOfSlice(permittedShellTypes, g.Shell) {
		return ValueError{Value: g.Shell, ValidValues: permittedShellTypes}
	}

	accountID := g.AccountName
	if accountID == "" {
		// No account specified. Can we use the most recent one?
		accountID = *appCtx.Config.LastUsedAccount
	}

	if accountID == "" {
		// TODO: Print help - no account id specified
		// return cmd.Usage()
		return errors.New("oopsie daisy")
	}

	account, ok := resolveApplicationInfo(appCtx.Config, g.BypassCache, accountID)
	if !ok {
		return UnknownAccountError(g.AccountName, FlagBypassCache)
	}

	if g.Role == "" {
		if account.MostRecentRole == "" {
			// cmd.PrintErrln("You must specify the --role flag with this command")
			return ErrNoRoleFlag
		}

		g.Role = account.MostRecentRole
	}

	// Only override g.TimeRemaining if the user didn't specify one on the command line
	if appCtx.Config.TimeRemaining != 0 && g.TimeRemaining == DefaultTimeRemaining {
		g.TimeRemaining = int(appCtx.Config.TimeRemaining)
	}

	var credentials CloudCredentials
	if g.Cloud == cloudAws {
		credentials = LoadAWSCredentialsFromEnvironment()
	} else if g.Cloud == cloudTencent {
		credentials = LoadTencentCredentialsFromEnvironment()
	}

	if credentials.ValidUntil(account, time.Duration(g.TimeRemaining)*time.Minute) {
		return echoCredentials(accountID, accountID, credentials, g.Output, g.Shell, g.OutputDirectory)
	}

	samlResponse, assertionStr, err := DiscoverConfigAndExchangeTokenForAssertion(ctx, NewHTTPClient(), appCtx.Config.Tokens, appCtx.OIDCDomain, appCtx.OIDCClientID, account.ID)
	if err != nil {
		return err
	}

	pair, ok := FindRoleInSAML(g.Role, samlResponse)
	if !ok {
		return UnknownRoleError(g.Role, g.AccountName)
	}

	if g.TimeToLive == 1 && appCtx.Config.TTL != 0 {
		g.TimeToLive = int(appCtx.Config.TTL)
	}

	if g.Cloud == cloudAws {
		session, _ := session.NewSession(&aws.Config{Region: aws.String(g.Region)})
		stsClient := sts.New(session)
		timeoutInSeconds := int64(3600 * g.TimeToLive)
		resp, err := stsClient.AssumeRoleWithSAMLWithContext(ctx, &sts.AssumeRoleWithSAMLInput{
			DurationSeconds: &timeoutInSeconds,
			PrincipalArn:    &pair.ProviderARN,
			RoleArn:         &pair.RoleARN,
			SAMLAssertion:   &assertionStr,
		})

		if err, ok := tryParseTimeToLiveError(err); ok {
			return err
		}

		if err != nil {
			return AWSError{
				InnerError: err,
				Message:    "failed to exchange credentials",
			}
		}

		credentials = CloudCredentials{
			AccessKeyID:     *resp.Credentials.AccessKeyId,
			Expiration:      resp.Credentials.Expiration.Format(time.RFC3339),
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
			credentialsType: g.Cloud,
		}
	} else {
		panic("not yet implemented")
	}

	if account != nil {
		account.MostRecentRole = g.Role
	}

	appCtx.Config.LastUsedAccount = &accountID
	return echoCredentials(accountID, accountID, credentials, g.Output, g.Shell, g.OutputDirectory)
}

func echoCredentials(id, name string, credentials CloudCredentials, outputType, shellType, outputDirectory string) error {
	switch outputType {
	case outputTypeEnvironmentVariable:
		credentials.WriteFormat(os.Stdout, shellType)
		return nil
	case outputTypeAWSCredentialsFile:
		acc := Account{ID: id, Name: name}
		if outputDirectory == "" {
			outputDirectory = "~/.aws"
		}
		newCliEntry := NewCloudCliEntry(credentials, &acc)
		return SaveCloudCredentialInCLI(outputDirectory, newCliEntry)
	default:
		return fmt.Errorf("%s is an invalid output type", outputType)
	}
}
