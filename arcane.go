package arcane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// API is the main struct for the Arcane SDK
type API struct {
	// Endpoint is the base URL for the API (e.g. https://arcane.dev)
	Endpoint string `json:"endpoint"`
	// Token is the bearer token for the API
	Token string `json:"token"`
}

// NewAPI creates a new API struct
func NewAPI(endpoint, token string) *API {
	return &API{
		Endpoint: endpoint + "/api/v1",
		Token:    token,
	}
}

func (t *API) post(path string, payload interface{}, response interface{}, headers ...map[string]string) error {
	url := t.Endpoint + path
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(headers) > 0 {
		for k, v := range headers[0] {
			req.Header.Set(k, v)
		}
	}

	return t.do(req, response)
}

type ErrorResponse struct {
	Message string `json:"message"`
}

func (t *API) do(req *http.Request, response interface{}) error {
	req.Header.Set("Authorization", t.Token)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	decode := json.NewDecoder(bytes.NewReader(body))
	decode.DisallowUnknownFields()
	decode.UseNumber()
	if resp.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := decode.Decode(&errorResponse); err != nil {
			return err
		}
		return errors.New(errorResponse.Message)
	}

	if err := decode.Decode(response); err != nil {
		return err
	}
	return nil
}

type CreateSecretRequest struct {
	Name                string `json:"name" example:"Secret Name"`
	Data                string `json:"data" example:"Secret Data"`
	ExpireDate          string `json:"expire_date" example:"2022-12-31"`
	Encrypt             bool   `json:"encrypt" example:"true"`
	CreateEncryptionKey bool   `json:"create_encryption_key" example:"true"`
	RsaBitSize          uint64 `json:"rsa_bit_size" example:"2048"`
	EncryptionKey       string `json:"encryption_key" example:"T8DXnoNbas8h26PC6fkNKvjR"`
	EncryptionType      string `json:"encryption_type" example:"AES"` // AES, RSA, etc.
}

type CreateSecretResponse struct {
	SecretKey            string `json:"secret_key"`
	EncryptionPrivateKey string `json:"encryption_private_key,omitempty"`
	EncryptionPublicKey  string `json:"encryption_public_key,omitempty"`
}

func (t *API) CreateSecret(payload *CreateSecretRequest) (*CreateSecretResponse, error) {
	response := &CreateSecretResponse{}
	err := t.post("/secrets", payload, response)
	return response, err
}

type GetSecretRequest struct {
	// ID is the ID of the secret
	ID string `json:"id"`
	// DecryptionKey is the key used to decrypt the secret
	DecryptionKey string `json:"decryption_key,omitempty"`
	// EncryptionType is the type of encryption used for the secret (e.g. AES, RSA, etc.)
	EncryptionType string `json:"encryption_type,omitempty"`
}

type GetSecretResponse struct {
	Name       string `json:"name" example:"Secret Name"`
	Data       string `json:"data" example:"Secret Data"`
	ExpireDate string `json:"expire_date,omitempty" example:"2022-12-31"`
}

func (g *GetSecretResponse) GetName() string {
	if g == nil || g.Name == "" {
		return ""
	}
	return g.Name
}

func (g *GetSecretResponse) GetData() string {
	if g == nil || g.Data == "" {
		return ""
	}
	return g.Data
}

func (g *GetSecretResponse) GetExpireDate() string {
	if g == nil || g.ExpireDate == "" || g.ExpireDate == "0001-01-01" {
		return ""
	}
	return g.ExpireDate
}

func (t *API) GetSecret(payload *GetSecretRequest) (*GetSecretResponse, error) {
	response := &GetSecretResponse{}
	err := t.post("/secrets/read", payload, response)
	return response, err
}
