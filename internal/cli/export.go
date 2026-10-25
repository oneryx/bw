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
	format := str(cmd, "format")
	// Checked here because library errors are printed as thrown errors ("Error: ...").
	if format != "" && !slices.Contains(bw.ExportFormats, format) {
		return output.Error("'%s' is not a supported export format. Supported formats: %s.", format, strings.Join(bw.ExportFormats, ", "))
	}
	orgID := str(cmd, "organizationid")
	if changed(cmd, "organizationid") {
		if err := checkGUID(orgID); err != nil {
			return errResp(err)
		}
	}
	password := strings.TrimSpace(str(cmd, "password"))
	// "--password" without a value (NoOptDefVal " ") asks for the password.
	if format == "encrypted_json" && changed(cmd, "password") && password == "" {
		if a.noInteraction {
			return output.Error("Export file password is required. Try again in interactive mode or provide it with --password <password>.")
		}
		password = promptSecret("Export file password:")
	}
	data, fileName, err := c.Export(context.Background(), bw.ExportOptions{Format: format, Password: password, OrganizationID: orgID})
	if err != nil {
		return jsError(err.Error())
	}
	return a.saveResultToFile(data, str(cmd, "output"), fileName)
}
