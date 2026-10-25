package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
)

func (a *App) runExport(cmd *cobra.Command, args []string) output.Response {
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	orgID := str(cmd, "organizationid")
	hasPassword := changed(cmd, "password")
	password := strings.TrimSpace(str(cmd, "password"))
	format := str(cmd, "format")
	if hasPassword && password != "" && format == "json" {
		format = "encrypted_json"
	}
	if format == "" {
		format = "csv"
	}
	if !slices.Contains(bw.ExportFormats, format) {
		return output.Error("'%s' is not a supported export format. Supported formats: %s.", format, strings.Join(bw.ExportFormats, ", "))
	}
	if changed(cmd, "organizationid") && !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	if format == "encrypted_json" && hasPassword && password == "" {
		password = promptSecret("Export file password:")
	}
	data, fileName, err := c.Export(context.Background(), bw.ExportOptions{Format: format, Password: password, OrganizationID: orgID})
	if err != nil {
		return jsError(err.Error())
	}
	return a.saveResultToFile(data, str(cmd, "output"), fileName)
}
