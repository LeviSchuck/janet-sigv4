(import ../sigv4)
(import ./example)
(import ./sign)

# Make a shallow clone
(def authorized-request (merge @{} example/request))
# Replace the headers with a clone, add in authorization
(put authorized-request :headers
  (merge
    (get authorized-request :headers @{})
    @{"Authorization" sign/auth}))
# Inspect the request
# This will error if there are problems, so use try!
(def inspected (sigv4/inspect-request authorized-request))
(printf "Inspected request %p" inspected)
# When options is supplied, always base it off the default
# options structure
(def opts (merge sigv4/default-options {
    # To verify with other dates, supply it explicitly
    :date example/date
}))

(def access-key-id (get inspected :access-key-id))
(printf "Inspected access key: %p" access-key-id)

# You should use the access-key-id to find a secret-access-key
(def secret-access-key example/secret-access-key)

# Then verify that this secret access key signed the request
# Will error out on things like date out of range or expired
(def verified (try
  (sigv4/verify-request secret-access-key inspected opts)
  ([err fib] err)))

# Of course, you should check what happened
(if (= true verified)
  (print "Success!")
  (printf "Did not verify: %p" verified)
  )
