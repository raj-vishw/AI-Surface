package fingerprint

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// signatureFile is one YAML file's top-level shape: a list of signatures
// under a "signatures" key, so one file can declare several related
// technologies (e.g. webservers.yaml holding nginx, Apache, generic).
type signatureFile struct {
	Signatures []Signature `yaml:"signatures"`
}

// CompiledSignature is a Signature with every regex pre-compiled once at
// load time — the matcher never calls regexp.Compile per observation
// (phase6.md §30).
type CompiledSignature struct {
	Signature
	compiledSignals   []compiledSignal
	compiledNegatives []compiledSignal
}

type compiledSignal struct {
	rule SignalRule
	re   *regexp.Regexp // nil when rule.Equals is used instead of Pattern
}

// LoadSignatures reads every "*.yaml" file directly inside dir (an
// fs.FS — typically the embedded default signature set, but any
// filesystem works, e.g. an operator-supplied signatures_path), validates
// every signature (phase6.md §28), compiles every regex once (phase6.md
// §29/§30), and returns them sorted by Name for deterministic evaluation
// order. Fails clearly and stops on the first invalid signature rather
// than silently skipping it.
func LoadSignatures(dir fs.FS) ([]CompiledSignature, error) {
	entries, err := fs.Glob(dir, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("listing signature files: %w", err)
	}
	sort.Strings(entries) // deterministic load order regardless of filesystem iteration order

	seen := make(map[string]string) // name -> file, for duplicate detection across files
	var out []CompiledSignature

	for _, entry := range entries {
		data, err := fs.ReadFile(dir, entry)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry, err)
		}

		var file signatureFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, &SignatureError{File: entry, Message: "malformed YAML: " + err.Error()}
		}

		for _, sig := range file.Signatures {
			compiled, err := validateAndCompile(entry, sig)
			if err != nil {
				return nil, err
			}
			if existing, dup := seen[compiled.Name]; dup {
				return nil, &SignatureError{File: entry, Name: compiled.Name,
					Message: fmt.Sprintf("duplicate signature name (already defined in %s)", existing)}
			}
			seen[compiled.Name] = entry
			out = append(out, compiled)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func validateAndCompile(file string, sig Signature) (CompiledSignature, error) {
	name := strings.TrimSpace(sig.Name)
	if name == "" {
		return CompiledSignature{}, &SignatureError{File: file, Message: "missing name"}
	}
	if !sig.Category.Valid() {
		return CompiledSignature{}, &SignatureError{File: file, Name: name,
			Message: fmt.Sprintf("missing or unrecognized category %q", sig.Category)}
	}
	if len(sig.Signals) == 0 {
		return CompiledSignature{}, &SignatureError{File: file, Name: name, Message: "must declare at least one signal"}
	}
	if sig.MinScore < 0 || sig.MinScore > 1 {
		return CompiledSignature{}, &SignatureError{File: file, Name: name,
			Message: fmt.Sprintf("min_score must be between 0.0 and 1.0, got %v", sig.MinScore)}
	}

	compiled := CompiledSignature{Signature: sig}

	signals, err := compileSignals(file, name, "signals", sig.Signals)
	if err != nil {
		return CompiledSignature{}, err
	}
	compiled.compiledSignals = signals

	negatives, err := compileSignals(file, name, "negative_signals", sig.NegativeSignals)
	if err != nil {
		return CompiledSignature{}, err
	}
	compiled.compiledNegatives = negatives

	return compiled, nil
}

func compileSignals(file, sigName, listName string, rules []SignalRule) ([]compiledSignal, error) {
	out := make([]compiledSignal, 0, len(rules))
	for i, rule := range rules {
		if !rule.Type.Valid() {
			return nil, &SignatureError{File: file, Name: sigName,
				Message: fmt.Sprintf("%s[%d]: unsupported signal type %q", listName, i, rule.Type)}
		}
		// weight is required for ordinary signals but negative_signals
		// use weight only informationally (a match disqualifies
		// regardless of magnitude) — still validate it's in range when
		// present, and default it to 1.0 for negatives that omit it.
		weight := rule.Weight
		if listName == "negative_signals" && weight == 0 {
			weight = 1.0
			rule.Weight = weight
		}
		if weight <= 0 || weight > 1 {
			return nil, &SignatureError{File: file, Name: sigName,
				Message: fmt.Sprintf("%s[%d]: weight must be between 0.0 (exclusive) and 1.0, got %v", listName, i, rule.Weight)}
		}
		if rule.Pattern == "" && rule.Equals == "" {
			return nil, &SignatureError{File: file, Name: sigName,
				Message: fmt.Sprintf("%s[%d]: must set either pattern or equals", listName, i)}
		}
		if rule.Pattern != "" && rule.Equals != "" {
			return nil, &SignatureError{File: file, Name: sigName,
				Message: fmt.Sprintf("%s[%d]: must not set both pattern and equals", listName, i)}
		}
		if rule.VersionGroup < 0 {
			return nil, &SignatureError{File: file, Name: sigName,
				Message: fmt.Sprintf("%s[%d]: version_group must not be negative", listName, i)}
		}

		cs := compiledSignal{rule: rule}
		if rule.Pattern != "" {
			// regexp.Compile uses Go's RE2 engine, which by construction
			// (no backreferences, no arbitrary lookaround) never exhibits
			// catastrophic backtracking (phase6.md §29) — no additional
			// safeguard is needed beyond using this package's regexp.
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, &SignatureError{File: file, Name: sigName,
					Message: fmt.Sprintf("%s[%d]: invalid regex %q: %v", listName, i, rule.Pattern, err)}
			}
			if rule.VersionGroup > re.NumSubexp() {
				return nil, &SignatureError{File: file, Name: sigName,
					Message: fmt.Sprintf("%s[%d]: version_group %d exceeds the pattern's %d capture group(s)", listName, i, rule.VersionGroup, re.NumSubexp())}
			}
			cs.re = re
		}
		out = append(out, cs)
	}
	return out, nil
}
