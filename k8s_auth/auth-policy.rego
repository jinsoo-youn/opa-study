package k8s.auth

jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 3600, # Cache response for an hour
    "tls_insecure_skip_verify": true,
})

jwks := jwks_request("https://hyperauth.tmaxcloud.org/auth/realms/tmax/protocol/openid-connect/certs").raw_body

verified := io.jwt.verify_rs256(input.spec.token, jwks)

error[msg] {
    not verified
    msg := "Token is not valid"
}

claims := payload {
    verified
	[_, payload, _] := io.jwt.decode(input.spec.token)
}

status = {
    "authenticated": true,
    "user": {
        "username": claims["preferred_username"],
        "groups": claims["group"]
    }
} {
    verified
} else = {
    "authenticated": false,
    "errors": error
} {
    not verified
}

decision = {
	"apiVersion": input.apiVersion,
	"kind": "TokenReview",
	"status": status
}