package jwt

import "testing"

// TestAlgorithm_Valid verifica se o algoritmo é válido.
func TestAlgorithm_Valid(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		want bool
	}{
		{name: "HS256", alg: AlgorithmHS256, want: true},
		{name: "none", alg: Algorithm("none"), want: false},
		{name: "RS256", alg: Algorithm("RS256"), want: false},
		{name: "vazio", alg: Algorithm(""), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.alg.Valid()
			if got != test.want {
				t.Errorf("Valid() = %v, want %v", got, test.want)
			}
		})
	}
}

// TestAlgorithm_String verifica se a string do algoritmo é correta.
func TestAlgorithm_String(t *testing.T) {
	if got := AlgorithmHS256.String(); got != "HS256" {
		t.Errorf("String() = %v, want %v", got, "HS256")
	}
}
