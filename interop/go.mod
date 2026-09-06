// Isolated module: pulls golang-jwt/jwt/v5 and go-jose/go-jose/v4 for
// cross-library interop tests only. Nothing here is reachable from
// github.com/NyeKo-ItL/jwt, so importers never see these dependencies.
module github.com/NyeKo-ItL/jwt/interop

go 1.27

require (
	github.com/NyeKo-ItL/jwt v0.0.0
	github.com/go-jose/go-jose/v4 v4.1.5
	github.com/golang-jwt/jwt/v5 v5.3.1
)

replace github.com/NyeKo-ItL/jwt => ../
