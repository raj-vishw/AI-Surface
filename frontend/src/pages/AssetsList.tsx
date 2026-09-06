import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Globe2, Search } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";
import { EmptyState } from "@/components/common/EmptyState";
import { ErrorState } from "@/components/common/ErrorState";
import { Pagination } from "@/components/common/Pagination";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/Table";
import { TableSkeleton } from "@/components/ui/Skeleton";
import { StatusBadge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/Select";
import { useAssets } from "@/hooks/useAssets";
import { useCursorPagination } from "@/hooks/useCursorPagination";
import { assetDisplayName, type AssetType } from "@/types/asset";
import { debounce, formatRelativeTime } from "@/lib/utils";

const ASSET_TYPES: AssetType[] = [
  "DOMAIN", "SUBDOMAIN", "HOST", "IP", "PORT", "SERVICE",
  "HTTP_ENDPOINT", "API_ENDPOINT", "AI_ENDPOINT", "REPOSITORY", "CLOUD_RESOURCE", "MODEL_ENDPOINT",
];

export default function AssetsList() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("search") ?? "");
  const navigate = useNavigate();
  const pagination = useCursorPagination(20);

  const type = (params.get("type") as AssetType) || undefined;
  const status = params.get("status") || undefined;

  const { data, isLoading, isError, error, refetch } = useAssets(
    { type, status: status as never, search: params.get("search") ?? undefined },
    pagination.pageParams,
  );

  const debouncedSetSearch = debounce((value: string) => {
    setParams((p) => {
      if (value) p.set("search", value);
      else p.delete("search");
      return p;
    });
    pagination.reset();
  }, 300);

  return (
    <div>
      <PageHeader title="Assets" description="Every discovered asset for this target — domains, subdomains, IPs, ports, services, and endpoints." />

      <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--color-border)] px-6 py-3">
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-[color:var(--color-text-faint)]" />
          <Input
            placeholder="Search hostname, IP, URL..."
            defaultValue={search}
            onChange={(e) => {
              setSearch(e.target.value);
              debouncedSetSearch(e.target.value);
            }}
            className="pl-8"
          />
        </div>
        <Select
          value={type ?? "all"}
          onValueChange={(v) => {
            setParams((p) => {
              if (v === "all") p.delete("type");
              else p.set("type", v);
              return p;
            });
            pagination.reset();
          }}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {ASSET_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={status ?? "all"}
          onValueChange={(v) => {
            setParams((p) => {
              if (v === "all") p.delete("status");
              else p.set("status", v);
              return p;
            });
            pagination.reset();
          }}
        >
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="ACTIVE">Active</SelectItem>
            <SelectItem value="DISCOVERED">Discovered</SelectItem>
            <SelectItem value="INACTIVE">Inactive</SelectItem>
            <SelectItem value="RETIRED">Retired</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {isError && <ErrorState error={error} onRetry={refetch} />}

      {!isError && isLoading && <TableSkeleton />}

      {!isError && !isLoading && data && data.items.length === 0 && (
        <EmptyState
          icon={Globe2}
          title="No assets match these filters"
          description="Try clearing a filter, or run a reconnaissance scan to discover new assets for this target."
        />
      )}

      {!isError && !isLoading && data && data.items.length > 0 && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>First Seen</TableHead>
                <TableHead>Last Seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((asset) => (
                <TableRow key={asset.id} className="cursor-pointer" onClick={() => navigate(`/assets/${asset.id}`)}>
                  <TableCell className="font-technical">{assetDisplayName(asset)}</TableCell>
                  <TableCell>{asset.type.replace(/_/g, " ")}</TableCell>
                  <TableCell>
                    <StatusBadge status={asset.status.toLowerCase()} />
                  </TableCell>
                  <TableCell className="font-technical">{Math.round(asset.confidence * 100)}%</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(asset.firstSeen)}</TableCell>
                  <TableCell className="text-[color:var(--color-text-muted)]">{formatRelativeTime(asset.lastSeen)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={data.total}
            shown={data.items.length}
            hasMore={data.hasMore}
            hasPrev={pagination.hasPrev}
            onNext={() => pagination.next(data.nextCursor)}
            onPrev={pagination.prev}
          />
        </>
      )}
    </div>
  );
}
