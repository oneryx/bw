// Package output mirrors the response model and printing rules of the
// official Bitwarden CLI (base-program.ts processResponse).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Options are the global output switches (--pretty, --raw, --response, --quiet, --cleanexit).
type Options struct {
	Pretty    bool
	Raw       bool
	Response  bool
	Quiet     bool
	CleanExit bool
}

// Response is the envelope printed by --response.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// MessageResponse is the "message" object type.
type MessageResponse struct {
	NoColor bool    `json:"noColor"`
	Object  string  `json:"object"`
	Title   string  `json:"title"`
	Message *string `json:"message"`
	Raw     *string `json:"raw,omitempty"`
}

// StringResponse is the "string" object type; a nil Data prints nothing.
type StringResponse struct {
	Object string  `json:"object"`
	Data   *string `json:"data"`
}

// ListResponse is the "list" object type.
type ListResponse struct {
	Object string `json:"object"`
	Data   any    `json:"data"`
}

// TemplateResponse is the "template" object type.
type TemplateResponse struct {
	Object   string `json:"object"`
	Template any    `json:"template"`
}

// Error makes a failed Response usable as an error value.
func (r *Response) Error() string { return r.Message }

func Success(data any) Response { return Response{Success: true, Data: data} }

func Error(format string, a ...any) Response {
	return Response{Success: false, Message: fmt.Sprintf(format, a...)}
}

func Message(title string, message string, raw string) Response {
	m := MessageResponse{Object: "message", Title: title}
	if message != "" {
		m.Message = &message
	}
	if raw != "" {
		m.Raw = &raw
	}
	return Success(m)
}

func String(s string) Response {
	return Success(StringResponse{Object: "string", Data: &s})
}

func List(items any) Response {
	return Success(ListResponse{Object: "list", Data: items})
}

func Template(t any) Response {
	return Success(TemplateResponse{Object: "template", Template: t})
}

// FileResponse carries binary content (attachments) for `bw serve`.
type FileResponse struct {
	Data     []byte
	FileName string
}

// Printer writes responses according to Options.
type Printer struct {
	Opts   Options
	Stdout io.Writer
	Stderr io.Writer
}

func NewPrinter(opts Options) *Printer {
	return &Printer{Opts: opts, Stdout: os.Stdout, Stderr: os.Stderr}
}

func (p *Printer) json(v any) string {
	indent := ""
	if p.Opts.Pretty {
		indent = "  "
	}
	return JSON(v, indent)
}

// JSON encodes like JavaScript's JSON.stringify: no HTML escaping, optional indent.
func JSON(v any, indent string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Print writes the response and returns the process exit code.
func (p *Printer) Print(r Response) int {
	if !r.Success {
		if !p.Opts.Quiet {
			if p.Opts.Response {
				writeLn(p.Stdout, p.json(r))
			} else {
				writeLn(p.Stderr, r.Message)
			}
		}
		if p.Opts.CleanExit {
			return 0
		}
		return 1
	}
	if p.Opts.Response {
		writeLn(p.Stdout, p.json(r))
		return 0
	}
	if r.Data == nil || p.Opts.Quiet {
		return 0
	}
	var out *string
	switch d := r.Data.(type) {
	case StringResponse:
		out = d.Data
	case ListResponse:
		s := p.json(d.Data)
		out = &s
	case TemplateResponse:
		s := p.json(d.Template)
		out = &s
	case MessageResponse:
		out = p.message(d)
	default:
		s := p.json(d)
		out = &s
	}
	if out != nil {
		writeLn(p.Stdout, *out)
	}
	return 0
}

func (p *Printer) message(m MessageResponse) *string {
	if p.Opts.Raw {
		return m.Raw
	}
	out := m.Title
	if m.Message != nil {
		if m.Title != "" {
			out += "\n"
		}
		out += *m.Message
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return &out
}

// writeLn prints a final line; like the official CLI, the trailing newline is
// omitted when the stream is not a terminal so values can be piped verbatim.
func writeLn(w io.Writer, s string) {
	if f, ok := w.(*os.File); ok && isTerminal(f) {
		fmt.Fprintln(w, s)
		return
	}
	fmt.Fprint(w, s)
}
