package correlation

import (
	"sort"
	"time"
)

// Node is one Observation materialized into a Graph — this package's
// in-memory counterpart of internal/domain/correlation.Node.
type Node struct {
	Ref        NodeRef
	Timestamp  time.Time
	Attributes map[string]any
}

// Graph is a bounded set of Nodes and the Edges a Strategy found between
// them (phase12.md §6). BuildGraph enforces Config's node/edge limits
// (phase12.md §62); ConnectedComponents splits a Graph into the separate,
// unrelated groupings it actually contains, since one Correlate call's
// Result commonly spans several independent situations for a target.
type Graph struct {
	Nodes []Node
	Edges []Edge
	// NodeLimited/EdgeLimited report whether BuildGraph had to drop
	// nodes/edges to stay within Config's bounds (phase12.md §62's
	// "explain the limitation").
	NodeLimited bool
	EdgeLimited bool
}

// nodeAttributes flattens the type-specific fields of obs (severity,
// category, verdict, IP, hostname, ...) into the small denormalized
// snapshot a Node carries — so downstream scoring/severity/chain-stage
// logic (see scoring.go, chain.go) needs only a Graph, never the original
// []Observation slice.
func nodeAttributes(obs Observation) map[string]any {
	attrs := map[string]any{"type": string(obs.Type)}
	for k, v := range obs.Attributes {
		attrs[k] = v
	}
	if obs.Severity != "" {
		attrs["severity"] = obs.Severity
	}
	if obs.Category != "" {
		attrs["category"] = obs.Category
	}
	if obs.Verdict != "" {
		attrs["verdict"] = obs.Verdict
	}
	if obs.IP != "" {
		attrs["ip"] = obs.IP
	}
	if obs.Hostname != "" {
		attrs["hostname"] = obs.Hostname
	}
	if obs.IndicatorType != "" {
		attrs["indicator_type"] = obs.IndicatorType
	}
	if obs.IndicatorValue != "" {
		attrs["indicator_value"] = obs.IndicatorValue
	}
	if obs.RuleCategory != "" {
		attrs["rule_category"] = obs.RuleCategory
	}
	return attrs
}

// nodeOf returns the Node for ref, if present.
func (g Graph) nodeOf(ref NodeRef) (Node, bool) {
	for _, n := range g.Nodes {
		if n.Ref == ref {
			return n, true
		}
	}
	return Node{}, false
}

// BuildGraph materializes every Observation referenced by at least one
// edge into a bounded Graph, deduplicating nodes by their (Type,
// ReferenceID) identity. An observation with no edge to anything else is
// never materialized as a node — there is nothing to correlate it with,
// so it never becomes its own trivial one-node "correlation" (see
// ConnectedComponents).
func BuildGraph(observations []Observation, edges []Edge, cfg Config) Graph {
	byRef := make(map[string]Observation, len(observations))
	for _, o := range observations {
		byRef[NodeRef{Type: o.Type, ReferenceID: o.ReferenceID}.Key()] = o
	}

	var g Graph
	seen := make(map[string]bool)
	addNode := func(ref NodeRef) {
		key := ref.Key()
		if seen[key] {
			return
		}
		obs, ok := byRef[key]
		if !ok {
			return
		}
		if len(g.Nodes) >= cfg.EffectiveMaxNodes() {
			g.NodeLimited = true
			return
		}
		seen[key] = true
		g.Nodes = append(g.Nodes, Node{Ref: ref, Timestamp: obs.Timestamp, Attributes: nodeAttributes(obs)})
	}

	maxEdges := cfg.EffectiveMaxEdges()
	for _, e := range edges {
		if len(g.Edges) >= maxEdges {
			g.EdgeLimited = true
			break
		}
		addNode(e.Source)
		addNode(e.Target)
		// Only keep an edge whose both endpoints were actually
		// materialized (the node limit may have dropped one).
		if _, ok := g.nodeOf(e.Source); !ok {
			continue
		}
		if _, ok := g.nodeOf(e.Target); !ok {
			continue
		}
		g.Edges = append(g.Edges, e)
	}

	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].Ref.Key() < g.Nodes[j].Ref.Key() })
	return g
}

// ConnectedComponents splits g into its separate connected components,
// each returned as its own Graph — a union-find over Edges, so two
// observations linked only transitively (A-B, B-C) still end up in the
// same component even without a direct A-C edge. A node with no edges at
// all forms its own single-node component. Components are returned in a
// deterministic order (phase12.md §25/§38): sorted by their lowest node
// key.
func ConnectedComponents(g Graph) []Graph {
	parent := make(map[string]string, len(g.Nodes))
	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	for _, n := range g.Nodes {
		parent[n.Ref.Key()] = n.Ref.Key()
	}
	for _, e := range g.Edges {
		union(e.Source.Key(), e.Target.Key())
	}

	groups := map[string][]Node{}
	for _, n := range g.Nodes {
		root := find(n.Ref.Key())
		groups[root] = append(groups[root], n)
	}

	var components []Graph
	for root, nodes := range groups {
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Ref.Key() < nodes[j].Ref.Key() })
		nodeSet := make(map[string]bool, len(nodes))
		for _, n := range nodes {
			nodeSet[n.Ref.Key()] = true
		}
		var edges []Edge
		for _, e := range g.Edges {
			if nodeSet[e.Source.Key()] {
				edges = append(edges, e)
			}
		}
		components = append(components, Graph{Nodes: nodes, Edges: edges})
		_ = root
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Nodes[0].Ref.Key() < components[j].Nodes[0].Ref.Key()
	})
	return components
}

// LimitDepth prunes g to only the nodes reachable from seed within
// maxDepth edge-hops (phase12.md §63) — a breadth-first traversal, never
// a full scan of every node in g. Nodes/edges outside the depth bound are
// dropped, and the return value reports whether anything was actually
// pruned.
func LimitDepth(g Graph, seed NodeRef, maxDepth int) (Graph, bool) {
	adjacency := map[string][]string{}
	for _, e := range g.Edges {
		adjacency[e.Source.Key()] = append(adjacency[e.Source.Key()], e.Target.Key())
		adjacency[e.Target.Key()] = append(adjacency[e.Target.Key()], e.Source.Key())
	}

	depth := map[string]int{seed.Key(): 0}
	queue := []string{seed.Key()}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if depth[cur] >= maxDepth {
			continue
		}
		for _, next := range adjacency[cur] {
			if _, visited := depth[next]; visited {
				continue
			}
			depth[next] = depth[cur] + 1
			queue = append(queue, next)
		}
	}

	var pruned Graph
	pruned.NodeLimited = len(depth) < len(g.Nodes)
	for _, n := range g.Nodes {
		if _, ok := depth[n.Ref.Key()]; ok {
			pruned.Nodes = append(pruned.Nodes, n)
		}
	}
	for _, e := range g.Edges {
		_, srcOK := depth[e.Source.Key()]
		_, dstOK := depth[e.Target.Key()]
		if srcOK && dstOK {
			pruned.Edges = append(pruned.Edges, e)
		}
	}
	return pruned, pruned.NodeLimited
}
