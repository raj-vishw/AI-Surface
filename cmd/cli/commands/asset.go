package commands

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"ai-recon-platform/internal/database"
	domainasset "ai-recon-platform/internal/domain/asset"
	domaintarget "ai-recon-platform/internal/domain/target"
	assetrepo "ai-recon-platform/internal/repository/asset"
	targetrepo "ai-recon-platform/internal/repository/target"
	assetsvc "ai-recon-platform/internal/service/asset"
	targetsvc "ai-recon-platform/internal/service/target"
)

// NewTargetCommand returns the `ai-recon target` command group.
//
// create/list started as Phase 2 development diagnostics for exercising
// internal/service/target directly (phase2.md §43) — this is still not
// the platform's full scan/target-management CLI (no update-name,
// deletion, etc.). authorize, however, is load-bearing as of Phase 3:
// it's the only way to move a target to AUTHORIZED, which `ai-recon scan`
// requires (phase3.md §7).
func NewTargetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Create, authorize, and list targets",
		Long: "Exercises internal/service/target's persistence directly. create/list are Phase 2\n" +
			"development diagnostics; authorize is required before `ai-recon scan` will run against\n" +
			"a target — a target is never authorized merely by existing (see SECURITY.md).",
	}
	cmd.AddCommand(newTargetCreateCommand(), newTargetListCommand(), newTargetAuthorizeCommand())
	return cmd
}

func newTargetAuthorizeCommand() *cobra.Command {
	var id, status string
	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Explicitly set a target's authorization status (default: AUTHORIZED)",
		Long: "Sets a target's authorization_status. This is the only way a target becomes\n" +
			"AUTHORIZED — required before `ai-recon scan` will run against it. Accepts\n" +
			"UNVERIFIED|AUTHORIZED|EXPIRED|REVOKED via --status; defaults to AUTHORIZED.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			targetUUID, err := uuid.Parse(id)
			if err != nil {
				return fmt.Errorf("invalid --id: %w", err)
			}

			ctx := context.Background()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			svc := targetsvc.NewService(db)
			updated, err := svc.UpdateAuthorizationStatus(ctx, targetUUID, domaintarget.AuthorizationStatus(status))
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "target %s authorization_status is now %s\n", updated.ID, updated.AuthorizationStatus)
			return err
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "target UUID (required — see `ai-recon target list`)")
	cmd.Flags().StringVar(&status, "status", string(domaintarget.AuthorizationAuthorized), "UNVERIFIED|AUTHORIZED|EXPIRED|REVOKED")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newTargetCreateCommand() *cobra.Command {
	var name, typ, value, description string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a target (authorization status starts UNVERIFIED)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			ctx := context.Background()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			svc := targetsvc.NewService(db)
			created, err := svc.Create(ctx, targetsvc.CreateInput{
				Name: name, Type: domaintarget.Type(typ), Value: value, Description: description,
			})
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "created target %s (%s: %s, authorization: %s)\n",
				created.ID, created.Type, created.Value, created.AuthorizationStatus)
			return err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "target display name (required)")
	cmd.Flags().StringVar(&typ, "type", "", "DOMAIN|HOST|IP|CIDR|URL|REPOSITORY|CLOUD_ACCOUNT (required)")
	cmd.Flags().StringVar(&value, "value", "", "the target value, e.g. example.com (required)")
	cmd.Flags().StringVar(&description, "description", "", "optional description")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("value")
	return cmd
}

func newTargetListCommand() *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List targets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			ctx := context.Background()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			svc := targetsvc.NewService(db)
			page, err := svc.List(ctx, targetrepo.ListFilter{Type: domaintarget.Type(typ)})
			if err != nil {
				return err
			}
			for _, t := range page.Items {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s  %-8s %-30s %s\n", t.ID, t.Type, t.Value, t.AuthorizationStatus); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by target type")
	return cmd
}

// NewAssetCommand returns the `ai-recon asset` command group — the same
// kind of development diagnostic as NewTargetCommand, for
// internal/service/asset. Not the future scan CLI.
func NewAssetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asset",
		Short: "[dev diagnostic] Upsert and list assets directly against the database",
	}
	cmd.AddCommand(newAssetUpsertCommand(), newAssetListCommand())
	return cmd
}

func newAssetUpsertCommand() *cobra.Command {
	var targetID, typ, hostname, ip, url, source string
	var port int
	var confidence float64
	cmd := &cobra.Command{
		Use:   "upsert",
		Short: "Upsert an asset by its computed identity (see internal/domain/asset.Identity)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			targetUUID, err := uuid.Parse(targetID)
			if err != nil {
				return fmt.Errorf("invalid --target-id: %w", err)
			}

			ctx := context.Background()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			input := assetsvc.Input{
				TargetID: targetUUID, Type: domainasset.Type(typ), Source: source,
				Confidence: domainasset.Confidence(confidence),
			}
			if hostname != "" {
				input.Hostname = &hostname
			}
			if ip != "" {
				input.IP = &ip
			}
			if url != "" {
				input.URL = &url
			}
			if port != 0 {
				input.Port = &port
			}

			svc := assetsvc.NewService(db)
			asset, created, err := svc.UpsertAsset(ctx, input)
			if err != nil {
				return err
			}

			verb := "updated"
			if created {
				verb = "created"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s asset %s (identity_key: %s, first_seen: %s, last_seen: %s)\n",
				verb, asset.ID, asset.IdentityKey, asset.FirstSeen.Format("2006-01-02T15:04:05Z"), asset.LastSeen.Format("2006-01-02T15:04:05Z"))
			return err
		},
	}
	cmd.Flags().StringVar(&targetID, "target-id", "", "owning target UUID (required)")
	cmd.Flags().StringVar(&typ, "type", "", "asset type, e.g. HOST, IP, HTTP_ENDPOINT, AI_ENDPOINT (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname (for HOST/DOMAIN/SUBDOMAIN types)")
	cmd.Flags().StringVar(&ip, "ip", "", "IP address (for IP type)")
	cmd.Flags().StringVar(&url, "url", "", "URL (for endpoint types)")
	cmd.Flags().IntVar(&port, "port", 0, "port (for PORT/SERVICE types)")
	cmd.Flags().StringVar(&source, "source", "manual", "discovery source attribution")
	cmd.Flags().Float64Var(&confidence, "confidence", 0.5, "confidence score, 0.0-1.0")
	_ = cmd.MarkFlagRequired("target-id")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

func newAssetListCommand() *cobra.Command {
	var targetID string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List assets for a target",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return fmt.Errorf("configuration is invalid: %w", err)
			}
			targetUUID, err := uuid.Parse(targetID)
			if err != nil {
				return fmt.Errorf("invalid --target-id: %w", err)
			}

			ctx := context.Background()
			db, err := database.Connect(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer db.Close()

			svc := assetsvc.NewService(db)
			page, err := svc.List(ctx, assetrepo.ListFilter{TargetID: targetUUID})
			if err != nil {
				return err
			}
			for _, a := range page.Items {
				identity := domainasset.StringField(a.Hostname)
				if identity == "" {
					identity = domainasset.StringField(a.URL)
				}
				if identity == "" {
					identity = domainasset.StringField(a.IP)
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s  %-15s %-30s %-10s confidence=%.2f\n",
					a.ID, a.Type, identity, a.Status, float64(a.Confidence)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&targetID, "target-id", "", "owning target UUID (required)")
	_ = cmd.MarkFlagRequired("target-id")
	return cmd
}
