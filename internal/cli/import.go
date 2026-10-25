package cli

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/importer"
	"github.com/oneryx/bw/internal/output"
)

func (a *App) runImport(cmd *cobra.Command, args []string) output.Response {
	format, path := "", ""
	if len(args) > 0 {
		format = args[0]
	}
	if len(args) > 1 {
		path = args[1]
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	if boolean(cmd, "formats") {
		list := strings.Join(bw.ImportFormats(), "\n")
		return output.Message("Supported input formats:", list, list)
	}
	if format == "" {
		return output.Error("`format` was not provided.")
	}
	if path == "" {
		return output.Error("`filepath` was not provided.")
	}
	if !slices.Contains(bw.ImportFormats(), format) {
		if slices.Contains(importer.OfficialFormats, format) {
			return output.Error("Import format `%s` is not supported by this CLI yet. Supported formats: %s.", format, strings.Join(bw.ImportFormats(), ", "))
		}
		return output.Error("Proper importer type required.")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return output.Error("%v", err)
	}
	err = c.Import(context.Background(), contents, bw.ImportOptions{
		Format:         format,
		OrganizationID: str(cmd, "organizationid"),
		Password: func() (string, error) {
			pw, err := a.getPassword("", str(cmd, "passwordfile"), str(cmd, "passwordenv"), "Import file password:")
			if err != nil {
				return "", errors.New("Import file password is required. Provide --passwordfile or --passwordenv, or run interactively.")
			}
			return pw, nil
		},
	})
	if err != nil {
		return errResp(err)
	}
	return output.Message("Imported "+path, "", "")
}
