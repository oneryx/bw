package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

// post sends a request that api.Client doesn't support (the read-only client
// never registers accounts or uploads files) and returns the response body.
func post(ctx context.Context, url, contentType string, body []byte, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: %s: %s", url, resp.Status, data)
	}
	return data, nil
}

// postJSON posts a JSON body without authentication.
func postJSON(ctx context.Context, url string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return post(ctx, url, "application/json", b, "")
}

// postFile uploads one file as multipart form data.
func postFile(ctx context.Context, url, token, field, fileName string, data []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, fileName)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = post(ctx, url, w.FormDataContentType(), buf.Bytes(), token)
	return err
}
