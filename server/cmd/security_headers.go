package main

import "net/http"

// SecurityHeaders applies conservative browser protections to every server
// response. TLS/HSTS remains the responsibility of the fronting proxy.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers := writer.Header()
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(writer, request)
	})
}
