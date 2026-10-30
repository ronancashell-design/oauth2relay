// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package secrets resolves secret placeholders in the configuration from
// AWS Secrets Manager, HashiCorp Vault, Azure Key Vault and the environment.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/redact"
)

// SecretManager defines the interface for a secret provider.
type SecretManager interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

// AWSSecretManager implements the SecretManager interface for AWS Secrets Manager.
type AWSSecretManager struct {
	client *secretsmanager.Client
}

func NewAWSSecretManager(cfg *config.AWSConfig) (*AWSSecretManager, error) {
	awsSDKConfig, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithSharedConfigProfile(cfg.Profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return &AWSSecretManager{
		client: secretsmanager.NewFromConfig(awsSDKConfig),
	}, nil
}

func (sm *AWSSecretManager) GetSecret(ctx context.Context, name string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: &name,
	}
	result, err := sm.client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve AWS secret %s: %w", name, err)
	}
	if result.SecretString == nil {
		return "", fmt.Errorf("secret string for %s is nil", name)
	}
	return *result.SecretString, nil
}

// envSecrets implements the SecretManager interface for environment
// variables.
type envSecrets struct{}

func (envSecrets) GetSecret(_ context.Context, name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return value, nil
}

// VaultSecretManager implements the SecretManager interface for HashiCorp Vault.
type VaultSecretManager struct {
	client    *vault.Client
	mount     string
	kvVersion int
}

const (
	defaultVaultMount      = "secret"
	defaultVaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func NewVaultSecretManager(cfg *config.VaultConfig) (*VaultSecretManager, error) {
	config := vault.DefaultConfig()
	if cfg.Address != "" {
		config.Address = cfg.Address
	}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}
	if err := vaultLogin(client, cfg.Auth); err != nil {
		return nil, err
	}

	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = defaultVaultMount
	}
	kvVersion := cfg.KVVersion
	if kvVersion == 0 {
		kvVersion = 2
	}
	return &VaultSecretManager{client: client, mount: mount, kvVersion: kvVersion}, nil
}

// vaultLogin authenticates the client with the configured auth method.
// Without an auth block the client keeps the token from VAULT_TOKEN.
func vaultLogin(client *vault.Client, auth *config.VaultAuthConfig) error {
	if auth == nil {
		return nil
	}
	mount := strings.Trim(auth.Mount, "/")
	if mount == "" {
		mount = auth.Type
	}

	switch auth.Type {
	case "approle":
		secretID := os.Getenv(auth.SecretIDEnv)
		if secretID == "" {
			return fmt.Errorf("environment variable %s for Vault secret ID not set", auth.SecretIDEnv)
		}
		appRoleAuth, err := approle.NewAppRoleAuth(auth.RoleID, &approle.SecretID{FromString: secretID},
			approle.WithMountPath(mount))
		if err != nil {
			return fmt.Errorf("failed to create approle auth: %w", err)
		}
		authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
		if err != nil {
			return fmt.Errorf("failed to login with approle: %w", err)
		}
		if authInfo == nil {
			return fmt.Errorf("no auth info was returned after login")
		}

	case "token":
		env := auth.TokenEnv
		if env == "" {
			env = "VAULT_TOKEN"
		}
		token := os.Getenv(env)
		if token == "" {
			return fmt.Errorf("environment variable %s for the Vault token not set", env)
		}
		client.SetToken(token)

	case "kubernetes":
		path := auth.TokenPath
		if path == "" {
			path = defaultVaultK8sJWTPath
		}
		jwtBytes, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the config
		if err != nil {
			return fmt.Errorf("failed to read Kubernetes service account token: %w", err)
		}
		secret, err := client.Logical().Write("auth/"+mount+"/login", map[string]interface{}{
			"role": auth.Role,
			"jwt":  strings.TrimSpace(string(jwtBytes)),
		})
		if err != nil {
			return fmt.Errorf("failed to login with kubernetes auth: %w", err)
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return fmt.Errorf("no token was returned after kubernetes login")
		}
		client.SetToken(secret.Auth.ClientToken)

	default:
		return fmt.Errorf("unsupported Vault auth type %q (valid: approle, token, kubernetes)", auth.Type)
	}
	return nil
}

func (sm *VaultSecretManager) GetSecret(ctx context.Context, name string) (string, error) {
	var data map[string]interface{}
	if sm.kvVersion == 1 {
		secret, err := sm.client.KVv1(sm.mount).Get(ctx, name)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve Vault secret %s: %w", name, err)
		}
		if secret != nil {
			data = secret.Data
		}
	} else {
		secret, err := sm.client.KVv2(sm.mount).Get(ctx, name)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve Vault secret %s: %w", name, err)
		}
		if secret != nil {
			data = secret.Data
		}
	}
	if data == nil {
		return "", fmt.Errorf("no data found for secret %s", name)
	}
	// Vault secrets are maps, so we marshal them to a JSON string to be consistent.
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Vault secret data to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// AzureSecretManager implements the SecretManager for Azure Key Vault.
type AzureSecretManager struct {
	client *azsecrets.Client
}

func NewAzureSecretManager(cfg *config.AzureConfig) (*AzureSecretManager, error) {
	cred, err := azureCredential(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}
	return &AzureSecretManager{client: client}, nil
}

// azureCredential picks the Azure identity described on AzureConfig.
func azureCredential(cfg *config.AzureConfig) (azcore.TokenCredential, error) {
	switch {
	case cfg.TenantID != "" && cfg.ClientID != "" && cfg.ClientSecretEnv != "":
		secret := os.Getenv(cfg.ClientSecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("environment variable %s for the Azure client secret not set", cfg.ClientSecretEnv)
		}
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, secret, nil)
	case cfg.ClientID != "":
		return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(cfg.ClientID),
		})
	default:
		return azidentity.NewDefaultAzureCredential(nil)
	}
}

func (sm *AzureSecretManager) GetSecret(ctx context.Context, name string) (string, error) {
	resp, err := sm.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve Azure secret %s: %w", name, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("secret value for %s is nil", name)
	}
	return *resp.Value, nil
}

// --- Secret Resolution Logic ---

// secretPlaceholderRe matches ${alias:secret_name} and
// ${alias:secret_name:json_key}. Only aliases that name a configured
// secrets manager, or env, are resolved; anything else is left unchanged.
var secretPlaceholderRe = regexp.MustCompile(`\$\{([^:{}]+):([^{}]+)\}`)

// Resolve replaces the secret placeholders in cfg with their values and
// registers each value for log redaction.
func Resolve(ctx context.Context, cfg *config.Config) error {
	return ResolveIn(ctx, cfg.SecretsManagers, cfg)
}

// ResolveIn replaces the secret placeholders in every exported string of
// target, a pointer to a struct, using the secrets managers in managers
// (checked with config.CheckSecretsManagers) and the environment (${env:...}).
// Each secret is fetched once and registered for log redaction. Programs
// that embed the relay use it for their own configuration.
func ResolveIn(ctx context.Context, managers map[string]*config.SecretsManagerConfig, target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("secrets: ResolveIn needs a non-nil pointer to a struct, got %T", target)
	}
	// Initialize all configured secret managers.
	byAlias := map[string]SecretManager{config.EnvAlias: envSecrets{}}
	for alias, smc := range managers {
		var sm SecretManager
		var err error
		switch smc.Type {
		case "aws_secrets_manager":
			sm, err = NewAWSSecretManager(smc.AWSConfig)
		case "hashicorp_vault":
			sm, err = NewVaultSecretManager(smc.VaultConfig)
		case "azure_key_vault":
			sm, err = NewAzureSecretManager(smc.AzureConfig)
		default:
			return fmt.Errorf("unsupported secret manager type: %s", smc.Type)
		}
		if err != nil {
			return fmt.Errorf("failed to initialize secret manager %s: %w", alias, err)
		}
		byAlias[alias] = sm
	}

	r := &secretResolver{ctx: ctx, managers: byAlias, cache: map[string]string{}}
	if err := r.resolveValue(v.Elem()); err != nil {
		return err
	}
	if r.resolved > 0 {
		slog.Info("Secret placeholders resolved", "placeholders", r.resolved, "fetches", len(r.cache))
	}
	return nil
}

// secretResolver walks the config and replaces secret placeholders. Each
// secret is fetched once, however many placeholders refer to it.
type secretResolver struct {
	ctx      context.Context
	managers map[string]SecretManager
	cache    map[string]string // "alias\x00name" -> raw secret value
	resolved int
}

func (r *secretResolver) resolveValue(v reflect.Value) error {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			return r.resolveValue(v.Elem())
		}
	case reflect.Interface:
		// Values decoded into interface{} (e.g. jwt_claims): a string held
		// in an interface cannot be set through Elem, so replace it whole.
		if v.IsNil() {
			return nil
		}
		inner := v.Elem()
		if inner.Kind() != reflect.String {
			return r.resolveValue(inner)
		}
		if v.CanSet() {
			resolved, err := r.resolveString(inner.String())
			if err != nil {
				return err
			}
			v.Set(reflect.ValueOf(resolved))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if err := r.resolveValue(v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := r.resolveValue(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		// Map elements cannot be set in place, so each value is resolved
		// on a copy and written back.
		for _, key := range v.MapKeys() {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(v.MapIndex(key))
			if err := r.resolveValue(elem); err != nil {
				return err
			}
			v.SetMapIndex(key, elem)
		}
	case reflect.String:
		if v.CanSet() {
			resolved, err := r.resolveString(v.String())
			if err != nil {
				return err
			}
			v.SetString(resolved)
		}
	}
	return nil
}

// resolveString replaces every secret placeholder in s.
func (r *secretResolver) resolveString(s string) (string, error) {
	var firstErr error
	out := secretPlaceholderRe.ReplaceAllStringFunc(s, func(match string) string {
		if firstErr != nil {
			return match
		}
		m := secretPlaceholderRe.FindStringSubmatch(match)
		alias, path := m[1], m[2]
		manager, ok := r.managers[alias]
		if !ok {
			return match // not a secret placeholder
		}
		secretName, jsonKey, _ := strings.Cut(path, ":")
		val, err := r.lookup(alias, manager, secretName, jsonKey)
		if err != nil {
			firstErr = err
			return match
		}
		r.resolved++
		redact.AddSecret(val)
		return val
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

func (r *secretResolver) lookup(alias string, manager SecretManager, secretName, jsonKey string) (string, error) {
	cacheKey := alias + "\x00" + secretName
	secretValue, ok := r.cache[cacheKey]
	if !ok {
		var err error
		secretValue, err = manager.GetSecret(r.ctx, secretName)
		if err != nil {
			return "", err
		}
		r.cache[cacheKey] = secretValue
	}

	if jsonKey == "" {
		return secretValue, nil
	}

	// If a JSON key is specified, parse the secret and extract the value.
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(secretValue), &data); err != nil {
		return "", fmt.Errorf("failed to parse secret %s as JSON: %w", secretName, err)
	}
	val, ok := data[jsonKey]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", jsonKey, secretName)
	}
	if s, ok := val.(string); ok {
		return s, nil
	}
	// Numbers, booleans and nested objects are used in their JSON form.
	b, err := json.Marshal(val)
	if err != nil {
		return "", fmt.Errorf("value for key %s in secret %s cannot be used: %w", jsonKey, secretName, err)
	}
	return string(b), nil
}
