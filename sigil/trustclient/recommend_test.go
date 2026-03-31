package trustclient

import (
	"strings"
	"testing"
)

func TestRecommend(t *testing.T) {
	tests := []struct {
		name              string
		score             float64
		totalAttestations int
		provisional       bool
		wantRec           Recommendation
		wantLabelContains string
	}{
		{
			name:              "no data",
			score:             0,
			totalAttestations: 0,
			wantRec:           RecommendUnknown,
			wantLabelContains: "unknown",
		},
		{
			name:              "provisional overrides high score",
			score:             0.95,
			totalAttestations: 2,
			provisional:       true,
			wantRec:           RecommendCaution,
			wantLabelContains: "provisional",
		},
		{
			name:              "well-trusted",
			score:             0.85,
			totalAttestations: 50,
			wantRec:           RecommendUse,
			wantLabelContains: "well-trusted",
		},
		{
			name:              "boundary at 0.7",
			score:             0.7,
			totalAttestations: 20,
			wantRec:           RecommendUse,
			wantLabelContains: "well-trusted",
		},
		{
			name:              "caution zone",
			score:             0.5,
			totalAttestations: 15,
			wantRec:           RecommendCaution,
			wantLabelContains: "mixed",
		},
		{
			name:              "boundary at 0.3",
			score:             0.3,
			totalAttestations: 10,
			wantRec:           RecommendCaution,
			wantLabelContains: "mixed",
		},
		{
			name:              "avoid zone",
			score:             0.2,
			totalAttestations: 30,
			wantRec:           RecommendAvoid,
			wantLabelContains: "poorly",
		},
		{
			name:              "zero score with attestations",
			score:             0,
			totalAttestations: 5,
			wantRec:           RecommendAvoid,
			wantLabelContains: "poorly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, label := Recommend(tt.score, tt.totalAttestations, tt.provisional)
			if rec != tt.wantRec {
				t.Errorf("Recommend() rec = %q, want %q", rec, tt.wantRec)
			}
			if !strings.Contains(label, tt.wantLabelContains) {
				t.Errorf("Recommend() label = %q, want to contain %q", label, tt.wantLabelContains)
			}
		})
	}
}
