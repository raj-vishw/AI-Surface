package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	discoverydns "ai-recon-platform/internal/discovery/dns"
	discoverysvc "ai-recon-platform/internal/discovery/service"
	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/logging"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewDNSScanCommand returns the `ai-recon dns-scan` command — Phase 5's
// canonical DNS discovery entry point, covering both record discovery and
// (via --subdomains, on by default) subdomain enumeration in one command
// (phase5.md §49). Like `scan`/`network-scan`, it requires the target to
// already exist and be authorized; dns-scan never creates or authorizes a
// target itself.
func NewDNSScanCommand() *cobra.Command {
	return newDNSCommand(false)
}

// NewSubdomainScanCommand returns `ai-recon subdomain-scan` — a thin
// alias over the exact same implementation as `dns-scan`, provided
// because phase5.md's own required verification (§73) invokes it by that
// name; it is not a second implementation (phase5.md §49's "do not create
// redundant CLI interfaces unless useful for compatibility" — this is
// exactly that compatibility case). It forces subdomain enumeration on
// and its table output highlights the subdomains section.
func NewSubdomainScanCommand() *cobra.Command {
	return newDNSCommand(true)
}

func newDNSCommand(subdomainMode bool) *cobra.Command {
	var (
		targetType     string
		recordTypesCSV string
		subdomains     bool
		wordlist       string
		maxCandidates  int
		maxDepth       int
		profile        string
		format         string
		timeout        string
		concurrency    int
		rate           float64
		resolversCSV   string
		dryRun         bool
	)

	use := "dns-scan --target <target>"
	short := "Run DNS record discovery (and, by default, subdomain enumeration) against an authorized target"
	if subdomainMode {
		use = "subdomain-scan --target <target>"
		short = "Run subdomain enumeration against an authorized target (an alias for `dns-scan --subdomains`)"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: "Runs the Phase 5 DNS discovery engine against an already-created, already-authorized\n" +
			"target: it queries the configured record types for the domain itself, optionally\n" +
			"enumerates subdomains (wordlist-based, with wildcard detection), and persists everything\n" +
			"through the Phase 2 persistence layer. It refuses to run against a target that is not\n" +
			"AUTHORIZED, and it never sends a DNS query in dry-run mode (security.dry_run, or\n" +
			"--dry-run).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, _ := cmd.Flags().GetString("target")
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("--target is required")
			}
			if subdomainMode && wordlist == "" && profile == "" {
				return fmt.Errorf("subdomain-scan requires --wordlist or --profile")
			}

			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			if !cfg.Discovery.DNS.Enabled {
				return fmt.Errorf("discovery.dns.enabled is false in the effective configuration")
			}

			if cmd.Flags().Changed("dry-run") {
				config.ApplyOverrides(cfg, config.Overrides{DryRun: &dryRun})
			}
			if cmd.Flags().Changed("timeout") {
				d, err := time.ParseDuration(timeout)
				if err != nil {
					return fmt.Errorf("invalid --timeout: %w", err)
				}
				cfg.Discovery.DNS.Timeout = d
			}
			if cmd.Flags().Changed("concurrency") {
				cfg.Discovery.DNS.MaxConcurrency = concurrency
			}
			if cmd.Flags().Changed("rate") {
				cfg.Discovery.DNS.RequestsPerSecond = rate
			}
			if cmd.Flags().Changed("max-candidates") {
				cfg.Discovery.DNS.Subdomains.MaxCandidates = maxCandidates
			}
			var maxDepthOverride *int
			if cmd.Flags().Changed("max-depth") {
				maxDepthOverride = &maxDepth
			}
			if resolversCSV != "" {
				var resolvers []string
				for _, r := range strings.Split(resolversCSV, ",") {
					if r = strings.TrimSpace(r); r != "" {
						resolvers = append(resolvers, r)
					}
				}
				cfg.Discovery.DNS.Resolvers = resolvers
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration after flag overrides: %w", err)
			}

			resolvedType := domaintarget.Type(strings.ToUpper(targetType))
			if resolvedType == "" {
				resolvedType = domaintarget.TypeDomain
			}

			var recordTypesOverride []discoverydns.RecordType
			if recordTypesCSV != "" {
				for _, t := range strings.Split(recordTypesCSV, ",") {
					recordTypesOverride = append(recordTypesOverride, discoverydns.RecordType(strings.ToUpper(strings.TrimSpace(t))))
				}
			}

			enumerateSubdomains := subdomains
			if subdomainMode {
				enumerateSubdomains = true
			}

			// Operational logs go to stderr unconditionally, so --format
			// json's stdout is always valid, log-free JSON (phase5.md §54).
			logger := logging.New(logging.Options{
				Level:  cfg.Logging.Level,
				Format: logging.Format(cfg.Logging.Format),
				Output: os.Stderr,
			})

			ctx := cmd.Context()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			targets := targetsvc.NewService(db)
			assets := assetsvc.NewService(db)
			discovery := discoverysvc.NewService(targets, assets, logger)

			summary, dryRunReport, err := discovery.RunDNS(ctx, discoverysvc.DNSRequest{
				TargetType: resolvedType, TargetValue: target,
				Profile: profile, RecordTypesOverride: recordTypesOverride, MaxDepthOverride: maxDepthOverride,
				EnumerateSubdomains: enumerateSubdomains, WordlistPath: wordlist,
				DryRun: cfg.Security.DryRun, Config: discoverydns.FromAppConfig(cfg.Discovery.DNS),
			})
			if err != nil {
				return err
			}

			if dryRunReport != nil {
				return printDNSDryRun(cmd, dryRunReport)
			}
			return printDNSSummary(cmd, summary, format, subdomainMode)
		},
	}

	cmd.Flags().String("target", "", "the domain to scan (required)")
	cmd.Flags().StringVar(&targetType, "target-type", "", "DOMAIN|HOST — defaults to DOMAIN")
	if !subdomainMode {
		cmd.Flags().StringVar(&recordTypesCSV, "record-types", "", "comma-separated record types (A,AAAA,CNAME,MX,NS,TXT,SOA,CAA) — overrides the profile/config default")
		cmd.Flags().BoolVar(&subdomains, "subdomains", true, "also enumerate subdomains (wordlist-based)")
	}
	cmd.Flags().StringVar(&wordlist, "wordlist", "", "path to a newline-delimited subdomain wordlist — overrides the profile/config default")
	cmd.Flags().IntVar(&maxCandidates, "max-candidates", 0, "override discovery.dns.subdomains.max_candidates")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 0, "override discovery.dns.subdomains.max_depth")
	cmd.Flags().StringVar(&profile, "profile", "", "named profile from configuration (e.g. quick, standard, comprehensive)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table|json")
	cmd.Flags().StringVar(&timeout, "timeout", "", "override discovery.dns.timeout (e.g. 3s)")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "override discovery.dns.max_concurrency")
	cmd.Flags().Float64Var(&rate, "rate", 0, "override discovery.dns.requests_per_second (0 = unlimited)")
	cmd.Flags().StringVar(&resolversCSV, "resolvers", "", "comma-separated \"host:port\" DNS servers to query — overrides discovery.dns.resolvers (empty = system resolver)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "override security.dry_run — report queries/candidates without resolving them")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func printDNSDryRun(cmd *cobra.Command, report *discoverysvc.DNSDryRunReport) error {
	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "DRY RUN\n\nTarget:\n%s\n\nRecord types:\n", report.Target); err != nil {
		return err
	}
	for _, rt := range report.RecordTypes {
		if _, err := fmt.Fprintln(out, rt); err != nil {
			return err
		}
	}
	if len(report.SubdomainCandidates) > 0 {
		if _, err := fmt.Fprint(out, "\nSubdomain candidates:\n"); err != nil {
			return err
		}
		for _, c := range report.SubdomainCandidates {
			if _, err := fmt.Fprintln(out, c); err != nil {
				return err
			}
		}
	}
	return nil
}

func printDNSSummary(cmd *cobra.Command, summary *discoverydns.Summary, format string, subdomainMode bool) error {
	switch format {
	case "json":
		// JSON output is the machine-readable contract: nothing but valid
		// JSON goes to stdout in this branch — operational logs are
		// already routed to stderr.
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	case "table", "":
		return printDNSTable(cmd, summary, subdomainMode)
	default:
		return fmt.Errorf("unrecognized --format %q (want table or json)", format)
	}
}

// printDNSTable renders the record-discovery table (phase5.md §55) and/or
// the subdomains table, followed by the aggregate scan summary
// (phase5.md §56). subdomain-scan's table skips the raw records section
// entirely — it's not what that command is asked to show — even though
// the underlying scan (and persistence) covers the domain's own records
// too, exactly like dns-scan does.
func printDNSTable(cmd *cobra.Command, summary *discoverydns.Summary, subdomainMode bool) error {
	out := cmd.OutOrStdout()

	if !subdomainMode {
		if _, err := fmt.Fprint(out, "DNS DISCOVERY\n\n"); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "NAME\tTYPE\tVALUE"); err != nil {
			return err
		}
		for _, r := range summary.RecordResults {
			if r.State != discoverydns.StateResolved {
				continue
			}
			for _, rec := range r.Records {
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", rec.Name, rec.Type, rec.Value); err != nil {
					return err
				}
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(summary.SubdomainResults) > 0 {
		if _, err := fmt.Fprint(out, "\nSUBDOMAINS\n\n"); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "SUBDOMAIN\tSTATE"); err != nil {
			return err
		}
		for _, sd := range summary.SubdomainResults {
			state := string(sd.State)
			if sd.WildcardAffected {
				state += " (WILDCARD)"
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\n", sd.Name, state); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	wildcardLine := "not detected"
	if summary.WildcardDetected {
		wildcardLine = "detected"
	}

	_, err := fmt.Fprintf(out, "\nDNS Discovery Summary\n\n"+
		"Target: %s\n\n"+
		"DNS names queried:      %d\n"+
		"Resolved:               %d\n"+
		"NXDOMAIN:               %d\n"+
		"No answer:              %d\n"+
		"Timeouts:               %d\n"+
		"Errors:                 %d\n\n"+
		"A records:              %d\n"+
		"AAAA records:           %d\n"+
		"CNAME records:          %d\n"+
		"MX records:             %d\n"+
		"NS records:             %d\n"+
		"TXT records:            %d\n"+
		"CAA records:            %d\n\n"+
		"Subdomains discovered:  %d\n"+
		"Wildcard DNS:           %s\n\n"+
		"Duration: %s\n",
		summary.Target, summary.NamesQueried, summary.Resolved, summary.NXDOMAIN, summary.NoAnswer,
		summary.Timeouts, summary.Errors,
		summary.RecordCounts[discoverydns.TypeA], summary.RecordCounts[discoverydns.TypeAAAA],
		summary.RecordCounts[discoverydns.TypeCNAME], summary.RecordCounts[discoverydns.TypeMX],
		summary.RecordCounts[discoverydns.TypeNS], summary.RecordCounts[discoverydns.TypeTXT],
		summary.RecordCounts[discoverydns.TypeCAA],
		summary.SubdomainsDiscovered, wildcardLine, summary.Duration,
	)
	return err
}
