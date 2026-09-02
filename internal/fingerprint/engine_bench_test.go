package fingerprint

import "testing"

// benchObservations builds n synthetic observations with a realistic mix
// of signals so the benchmark exercises the full matcher, not just a
// single always-matching header (phase6.md §35).
func benchObservations(n int) []Observation {
	obs := make([]Observation, n)
	for i := range obs {
		port := 5432
		obs[i] = Observation{
			Headers: map[string]string{
				"Server":       "nginx/1.25.3",
				"CF-Ray":       "abc123-SJC",
				"X-Powered-By": "Express",
			},
			CookieNames: []string{"JSESSIONID", "csrftoken"},
			APIPaths:    []string{"/api/v1/users", "/v1/chat/completions"},
			URLPath:     "/api/v1/users",
			ContentType: "application/json",
			Port:        &port,
		}
	}
	return obs
}

// BenchmarkEngine_Evaluate_10Assets measures throughput at a small scale
// (phase6.md §35).
func BenchmarkEngine_Evaluate_10Assets(b *testing.B) {
	benchmarkEvaluate(b, 10)
}

// BenchmarkEngine_Evaluate_100Assets measures throughput at a medium
// scale.
func BenchmarkEngine_Evaluate_100Assets(b *testing.B) {
	benchmarkEvaluate(b, 100)
}

// BenchmarkEngine_Evaluate_1000Assets measures throughput at the largest
// required scale (phase6.md §35: "1,000 assets / 100 signatures"). No
// network I/O is performed — purely in-memory matching against the
// built-in signature set.
func BenchmarkEngine_Evaluate_1000Assets(b *testing.B) {
	benchmarkEvaluate(b, 1000)
}

func benchmarkEvaluate(b *testing.B, n int) {
	sigs, err := LoadDefaultSignatures()
	if err != nil {
		b.Fatalf("LoadDefaultSignatures: %v", err)
	}
	e := NewEngine(sigs, EngineConfig{MinConfidence: 0})
	observations := benchObservations(n)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, o := range observations {
			_ = e.Evaluate(o)
		}
	}
}
