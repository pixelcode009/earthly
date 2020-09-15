package llbutil

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/secrets"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MaxSecretSize is the maximum byte length allowed for a secret
const MaxSecretSize = 500 * 1024 // 500KB

func NewSecretProvider(store secrets.SecretStore) session.Attachable {
	return &secretProvider{
		store:        store,
		secretServer: os.Getenv("SECRET_SERVER"),
		authToken:    os.Getenv("SECRET_TOKEN"),
	}
}

type secretProvider struct {
	store        secrets.SecretStore
	secretServer string
	authToken    string
}

func (sp *secretProvider) Register(server *grpc.Server) {
	secrets.RegisterSecretsServer(server, sp)
}

func (sp *secretProvider) getSecretFromServer(path string) ([]byte, error) {
	client := &http.Client{}

	url := fmt.Sprintf("%s/api/v0/secrets/%s", sp.secretServer, path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("auth", sp.authToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.NotFound, "not found") // TODO figure out 2nd arg
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (sp *secretProvider) GetSecret(ctx context.Context, req *secrets.GetSecretRequest) (*secrets.GetSecretResponse, error) {
	dt, err := sp.store.GetSecret(ctx, req.ID)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			dt, err = sp.getSecretFromServer(req.ID)
			if err != nil {
				return nil, err
			}
			//dt = []byte(fmt.Sprintf("secret for %v", req.ID))
		} else {
			return nil, err
		}
	}
	if l := len(dt); l > MaxSecretSize {
		return nil, errors.Errorf("invalid secret size %d", l)
	}

	return &secrets.GetSecretResponse{
		Data: dt,
	}, nil
}

func FromMap(m map[string][]byte) session.Attachable {
	return NewSecretProvider(mapStore(m))
}

type mapStore map[string][]byte

func (m mapStore) GetSecret(ctx context.Context, id string) ([]byte, error) {
	v, ok := m[id]
	if !ok {
		return nil, errors.WithStack(secrets.ErrNotFound)
	}
	return v, nil
}
