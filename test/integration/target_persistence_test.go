//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/repository/pagination"
	targetrepo "ai-recon-platform/internal/repository/target"
	targetsvc "ai-recon-platform/internal/service/target"
)

// uniqueValue returns a value guaranteed not to collide with another test
// run against the same shared database.
func uniqueValue(prefix string) string {
	return fmt.Sprintf("%s-%s.integration.test", prefix, uuid.New().String())
}

func TestTargetPersistence_CreateAndGet(t *testing.T) {
	pool := setupDB(t)
	svc := targetsvc.NewService(pool)
	ctx := context.Background()

	value := uniqueValue("create")
	created, err := svc.Create(ctx, targetsvc.CreateInput{
		Name: "integration test target", Type: domaintarget.TypeDomain, Value: value,
	})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("expected a server-assigned ID")
	}
	if created.AuthorizationStatus != domaintarget.AuthorizationUnverified {
		t.Errorf("new target authorization status = %q, want UNVERIFIED", created.AuthorizationStatus)
	}

	fetched, err := svc.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if fetched.Value != value {
		t.Errorf("fetched value = %q, want %q", fetched.Value, value)
	}

	byValue, err := svc.GetByValue(ctx, domaintarget.TypeDomain, value)
	if err != nil {
		t.Fatalf("GetByValue() failed: %v", err)
	}
	if byValue.ID != created.ID {
		t.Errorf("GetByValue returned a different target")
	}
}

func TestTargetPersistence_DuplicateRejected(t *testing.T) {
	pool := setupDB(t)
	svc := targetsvc.NewService(pool)
	ctx := context.Background()

	value := uniqueValue("dup")
	input := targetsvc.CreateInput{Name: "t1", Type: domaintarget.TypeDomain, Value: value}
	if _, err := svc.Create(ctx, input); err != nil {
		t.Fatalf("first Create() failed: %v", err)
	}
	if _, err := svc.Create(ctx, input); err == nil {
		t.Fatal("expected an error creating a duplicate (type, value) target")
	}
}

func TestTargetPersistence_AuthorizationNeverImplicit(t *testing.T) {
	pool := setupDB(t)
	svc := targetsvc.NewService(pool)
	ctx := context.Background()

	created, err := svc.Create(ctx, targetsvc.CreateInput{
		Name: "auth test", Type: domaintarget.TypeDomain, Value: uniqueValue("auth"),
	})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	authorized, err := svc.IsAuthorized(ctx, created.ID)
	if err != nil {
		t.Fatalf("IsAuthorized() failed: %v", err)
	}
	if authorized {
		t.Fatal("a newly created target must never be authorized by default")
	}

	updated, err := svc.UpdateAuthorizationStatus(ctx, created.ID, domaintarget.AuthorizationAuthorized)
	if err != nil {
		t.Fatalf("UpdateAuthorizationStatus() failed: %v", err)
	}
	if !updated.IsAuthorized() {
		t.Fatal("expected the target to be authorized after an explicit status update")
	}

	authorized, err = svc.IsAuthorized(ctx, created.ID)
	if err != nil {
		t.Fatalf("IsAuthorized() failed: %v", err)
	}
	if !authorized {
		t.Fatal("IsAuthorized should reflect the persisted authorization status")
	}
}

func TestTargetPersistence_Pagination(t *testing.T) {
	pool := setupDB(t)
	svc := targetsvc.NewService(pool)
	ctx := context.Background()

	prefix := uniqueValue("page")
	const total = 5
	for i := 0; i < total; i++ {
		_, err := svc.Create(ctx, targetsvc.CreateInput{
			Name: "pagination test", Type: domaintarget.TypeDomain, Value: fmt.Sprintf("%d.%s", i, prefix),
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
	}

	seen := map[uuid.UUID]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := svc.List(ctx, targetrepo.ListFilter{
			Type:       domaintarget.TypeDomain,
			Pagination: pagination.Params{Limit: 2, Cursor: cursor},
		})
		if err != nil {
			t.Fatalf("List() failed: %v", err)
		}
		for _, item := range page.Items {
			seen[item.ID] = true
		}
		pages++
		if page.NextCursor == "" || pages > 100 {
			break
		}
		cursor = page.NextCursor
	}

	if pages < 2 {
		t.Errorf("expected pagination to span multiple pages with a page size of 2, got %d page(s)", pages)
	}
}
