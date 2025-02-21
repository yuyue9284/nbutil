package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

type NBFile struct {
	EncryptedData string `json:"encrypted_data"`
	KeyVaultName  string `json:"key_vault_name"`
	SecretName    string `json:"secret_name"`
	Data          string `json:"data"`
}

func parseNBFile(filename string) error {
	// 1. Read the .nb file
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read .nb file: %w", err)
	}

	// 2. Parse the JSON content
	var nbFile NBFile
	err = json.Unmarshal(fileContent, &nbFile)
	if err != nil {
		return fmt.Errorf("failed to parse .nb file: %w", err)
	}
	cred, err := azidentity.NewInteractiveBrowserCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azsecrets.NewClient("https://"+nbFile.KeyVaultName+".vault.azure.net", cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	ctx := context.Background()
	getResp, err := client.GetSecret(ctx, nbFile.SecretName, "", nil)
	if err != nil {
		return fmt.Errorf("failed to get secret from Key Vault: %w", err)
	}
	key := getResp.Value

	if nbFile.Data == "" {
		// Decrypt from encrypted_data
		if nbFile.EncryptedData == "" {
			return fmt.Errorf("encrypted_data is empty, cannot decrypt")
		}

		// 4. Decrypt the data
		ciphertext, err := base64.StdEncoding.DecodeString(nbFile.EncryptedData)
		if err != nil {
			return fmt.Errorf("failed to decode ciphertext: %w", err)
		}

		plaintext, err := decryptAES(ciphertext, []byte(*key))
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}

		nbFile.Data = string(plaintext)

	} else {
		// Encrypt the data
		encryptedData, err := encryptContent(nbFile.Data, []byte(*key))
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}
		nbFile.EncryptedData = encryptedData
		nbFile.Data = "" // Clear data after encryption
	}

	// 5. Write back to the file
	updatedFileContent, err := json.MarshalIndent(nbFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated .nb file: %w", err)
	}

	err = os.WriteFile(filename, updatedFileContent, 0644)
	if err != nil {
		return fmt.Errorf("failed to write updated .nb file: %w", err)
	}

	return nil
}

func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	nonce := ciphertext[:12]
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func encryptContent(plaintext string, key []byte) (string, error) {
	ciphertext, err := encryptAES([]byte(plaintext), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	filename := "test.json.nb"
	err := parseNBFile(filename)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
