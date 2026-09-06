import {
  LayoutDashboard,
  Globe,
  ShieldAlert,
  Gauge,
  BellRing,
  Radar,
  Search,
  Waypoints,
  Siren,
  History,
  ShieldQuestion,
  Fingerprint,
  BarChart3,
  BrainCircuit,
  FileText,
  FileCheck2,
  ScanSearch,
  ScrollText,
  Settings,
  type LucideIcon,
} from "lucide-react";

/**
 * Sidebar structure (spec §9), pruned to what this backend actually
 * models (spec §9's own instruction: "do not create fake modules merely
 * to make the sidebar look larger"). Two deliberate departures from the
 * spec's suggested structure, both documented in the frontend
 * implementation report:
 *
 *  - Domains/Subdomains/DNS/Services are NOT separate nav items — they
 *    are all Asset.Type values (see src/types/asset.ts), so they're
 *    filtered views of one Assets page, not separate routes.
 *  - "Jobs" is omitted entirely — this backend has no job queue at all
 *    (cmd/worker has no job consumer; confirmed by inspection), so a
 *    Jobs monitor would have nothing real to show.
 */
export interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [{ label: "Dashboard", href: "/dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Reconnaissance",
    items: [
      { label: "Assets", href: "/assets", icon: Globe },
      { label: "Technologies", href: "/technologies", icon: Fingerprint },
      { label: "Reconnaissance", href: "/reconnaissance", icon: Radar },
    ],
  },
  {
    label: "Security",
    items: [
      { label: "Findings", href: "/findings", icon: ShieldAlert },
      { label: "Risk", href: "/risk", icon: Gauge },
      { label: "Alerts", href: "/alerts", icon: BellRing },
      { label: "Detections", href: "/detections", icon: Siren },
    ],
  },
  {
    label: "Investigation",
    items: [
      { label: "Investigations", href: "/investigations", icon: Search },
      { label: "Attack Chains", href: "/attack-chains", icon: Waypoints },
      { label: "Incidents", href: "/incidents", icon: ShieldQuestion },
      { label: "Timeline", href: "/timeline", icon: History },
    ],
  },
  {
    label: "Intelligence",
    items: [{ label: "Threat Intelligence", href: "/intelligence", icon: ScanSearch }],
  },
  {
    label: "Analytics",
    items: [{ label: "Analytics", href: "/analytics", icon: BarChart3 }],
  },
  {
    label: "AI",
    items: [{ label: "AI Investigation", href: "/ai", icon: BrainCircuit }],
  },
  {
    label: "Reporting",
    items: [
      { label: "Reports", href: "/reports", icon: FileText },
      { label: "Evidence", href: "/evidence", icon: FileCheck2 },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Scan History", href: "/scans", icon: History },
      { label: "Audit Log", href: "/audit", icon: ScrollText },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];
