// Package template implements the restricted templating language for
// keg configuration values (CONCEPT.md §4.6): the only accessible
// contexts are .Vars and (when explicitly enabled) .Env, and the only
// function is `default`. Anything else is a configuration error — the
// policy surface must never be scriptable.
package template

import (
	"fmt"
	"strings"
	"text/template"
	"text/template/parse"
)

// Context is the data a template may access. Env == nil means host
// environment access is not enabled (template_env.allow_env: false).
type Context struct {
	Vars map[string]string
	Env  map[string]string // nil = disabled; access is a config error
}

// WithVar returns a copy of ctx with one additional variable (test helper).
func (ctx Context) WithVar(key, value string) Context {
	vars := make(map[string]string, len(ctx.Vars)+1)
	for k, v := range ctx.Vars {
		vars[k] = v
	}
	vars[key] = value
	return Context{Vars: vars}
}

// defaultFn implements `default fallback value`.
func defaultFn(fallback, value string) string {
	if value == "" {
		return fallback
	}
	return value
}

// funcMap is closed: adding functions here widens the config language.
var funcMap = template.FuncMap{
	"default": defaultFn,
}

// Apply renders text against ctx. Errors carry a line reference so users
// can locate the offending entry in multi-line YAML files.
func Apply(text string, ctx Context) (string, error) {
	if !strings.Contains(text, "{{") {
		return text, nil // fast path: nothing to render
	}
	if ctx.Env == nil && strings.Contains(text, ".Env") {
		return "", fmt.Errorf("template %q: .Env is not available here — "+
			"enable template_env.allow_env in the user config", text)
	}

	tmpl, err := template.New("v").Funcs(funcMap).Parse(text)
	if err != nil {
		return "", fmt.Errorf("template %q: %w", text, err)
	}
	if err := validateRequiredVars(tmpl.Tree, text, ctx.Vars); err != nil {
		return "", fmt.Errorf("template %q: %w", text, err)
	}

	tmpl = tmpl.Option("missingkey=zero")
	var out strings.Builder
	if err := tmpl.Execute(&out, map[string]any{"Vars": ctx.Vars, "Env": ctx.Env}); err != nil {
		return "", fmt.Errorf("template %q: %w", text, err)
	}
	return out.String(), nil
}

// validateRequiredVars errors when a .Vars.<key> reference outside of a
// `default` call addresses a variable that does not exist. Inside default
// a missing variable is the intended trigger for the fallback.
func validateRequiredVars(tree *parse.Tree, text string, vars map[string]string) error {
	return walkList(tree.Root, text, false, func(field *parse.FieldNode, guarded bool) error {
		if len(field.Ident) < 2 || field.Ident[0] != "Vars" || guarded {
			return nil
		}
		key := field.Ident[1]
		if _, ok := vars[key]; ok {
			return nil
		}
		line := lineOf(text, field.Position())
		return fmt.Errorf("line %d: variable %q is not defined (wrap the reference in default \"…\" to allow a fallback)", line, key)
	})
}

func minPos(a, b parse.Pos) parse.Pos {
	if a < b {
		return a
	}
	return b
}

func lineOf(text string, pos parse.Pos) int {
	return 1 + strings.Count(text[:minPos(pos, parse.Pos(len(text)))], "\n")
}

// walkList traverses template nodes depth-first, reporting every .Vars
// field access together with whether it sits inside a default() call.
func walkList(list *parse.ListNode, text string, guarded bool, visit func(*parse.FieldNode, bool) error) error {
	if list == nil {
		return nil
	}
	for _, node := range list.Nodes {
		switch n := node.(type) {
		case *parse.ActionNode:
			if err := walkPipe(n.Pipe, text, guarded, visit); err != nil {
				return err
			}
		case *parse.IfNode:
			if err := walkBranch(&n.BranchNode, text, visit); err != nil {
				return err
			}
		case *parse.RangeNode:
			if err := walkBranch(&n.BranchNode, text, visit); err != nil {
				return err
			}
		case *parse.WithNode:
			if err := walkBranch(&n.BranchNode, text, visit); err != nil {
				return err
			}
		case *parse.TextNode:
			// literal content: nothing to validate
		}
	}
	return nil
}

func walkBranch(branch *parse.BranchNode, text string, visit func(*parse.FieldNode, bool) error) error {
	if err := walkPipe(branch.Pipe, text, false, visit); err != nil {
		return err
	}
	if err := walkList(branch.List, text, false, visit); err != nil {
		return err
	}
	return walkList(branch.ElseList, text, false, visit)
}

func walkPipe(pipe *parse.PipeNode, text string, guarded bool, visit func(*parse.FieldNode, bool) error) error {
	if pipe == nil {
		return nil
	}
	for _, cmd := range pipe.Cmds {
		ident, isFunc := cmd.Args[0].(*parse.IdentifierNode)
		if isFunc && ident.Ident != "default" {
			line := 1 + strings.Count(text[:minPos(cmd.Position(), parse.Pos(len(text)))], "\n")
			return fmt.Errorf("line %d: function %q is not available (restricted language: only default)",
				line, ident.Ident)
		}
		isDefault := isFunc
		for i, arg := range cmd.Args {
			// The value argument of default(...) may reference missing vars.
			guardedChild := guarded || (isDefault && i == 2)
			switch a := arg.(type) {
			case *parse.FieldNode:
				if err := visit(a, guardedChild); err != nil {
					return err
				}
			case *parse.ChainNode:
				if fn, ok := a.Node.(*parse.FieldNode); ok {
					if err := visit(fn, guardedChild); err != nil {
						return err
					}
				}
			case *parse.PipeNode: // parenthesized pipelines
				if err := walkPipe(a, text, guardedChild, visit); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
