// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package config

import (
	"fmt"
	"os"
)

// EnvAlias is the built-in placeholder alias for environment variables:
// ${env:NAME} or ${env:NAME:json_key}. It needs no secrets_managers entry.
const EnvAlias = "env"

// --- Configuration checks ---

// CheckSecretsManagers checks secrets manager definitions, so that
// mistakes are reported when a configuration is loaded rather than when a
// secret is first fetched. Config.Check calls it for secrets_managers;
// programs with their own configuration call it before secrets.ResolveIn.
func CheckSecretsManagers(managers map[string]*SecretsManagerConfig) error {
	return validateSecretsManagers(managers)
}

// validateSecretsManagers checks each secrets manager definition.
func validateSecretsManagers(managers map[string]*SecretsManagerConfig) error {
	for alias, smc := range managers {
		if alias == EnvAlias {
			return fmt.Errorf("secrets_managers: %q is reserved for environment variables (${env:NAME}); choose another alias", EnvAlias)
		}
		if smc == nil {
			return fmt.Errorf("secrets_managers.%s is empty", alias)
		}
		switch smc.Type {
		case "aws_secrets_manager":
		case "hashicorp_vault":
			vc := smc.VaultConfig
			if vc.Address == "" && os.Getenv("VAULT_ADDR") == "" {
				return fmt.Errorf("secrets_managers.%s: address is required (or set VAULT_ADDR)", alias)
			}
			if vc.KVVersion != 0 && vc.KVVersion != 1 && vc.KVVersion != 2 {
				return fmt.Errorf("secrets_managers.%s: kv_version must be 1 or 2", alias)
			}
			if a := vc.Auth; a != nil {
				switch a.Type {
				case "approle":
					if a.RoleID == "" || a.SecretIDEnv == "" {
						return fmt.Errorf("secrets_managers.%s: approle auth requires role_id and secret_id_env", alias)
					}
				case "token":
				case "kubernetes":
					if a.Role == "" {
						return fmt.Errorf("secrets_managers.%s: kubernetes auth requires role", alias)
					}
				default:
					return fmt.Errorf("secrets_managers.%s: unsupported auth type %q (valid: approle, token, kubernetes)", alias, a.Type)
				}
			}
		case "azure_key_vault":
			ac := smc.AzureConfig
			if ac.VaultURL == "" {
				return fmt.Errorf("secrets_managers.%s: vault_url is required", alias)
			}
			partial := ac.TenantID != "" || ac.ClientSecretEnv != ""
			if partial && (ac.TenantID == "" || ac.ClientID == "" || ac.ClientSecretEnv == "") {
				return fmt.Errorf("secrets_managers.%s: a service principal needs tenant_id, client_id and client_secret_env", alias)
			}
		}
	}
	return nil
}
