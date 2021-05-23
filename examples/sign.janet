(import ../sigv4)
(import ./example)

(def auth (sigv4/authorization-header
  example/access-key-id
  example/secret-access-key
  example/region
  example/service
  example/request))

(print "Authorization: " auth)
