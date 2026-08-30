package jwt

// Algorithm representa o algoritmo de assinatura usado para criar e verificar tokens JWT.
type Algorithm string

const (
	AlgorithmHS256 Algorithm = "HS256"
	//Futuro HS384 e HS512
)

func (a Algorithm) String() string {
	return string(a)
}

func (a Algorithm) Valid() bool {
	switch a {
	case AlgorithmHS256:
		return true
	default:
		return false
	}
}
