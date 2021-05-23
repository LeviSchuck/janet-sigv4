# Copyright (c) 2021 Levi Schuck
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

(use janetls)

# TODO handle x-amz-content-sha256 UNSIGNED_PAYLOAD
# TODO support X-Goog-Date and other prefixed headers / queries
# TODO support X-Amz-Security-Token
# TODO maybe check the request date isn't far into the future
# TODO verify the algorithm is as expected

(defn- hmac-raw [key body] (md/hmac :sha256 key body :raw))
(defn signature-key [key date region service &opt req-type protocol-type]
  (default req-type "aws4_request")
  (default protocol-type "AWS4")
  (-> (string protocol-type key)
    (hmac-raw date)
    (hmac-raw region)
    (hmac-raw service)
    (hmac-raw req-type)))

(def- aws-duplicate-spaces (peg/compile '(at-least 2 " ")))

(def default-options {
  :alg "AWS4-HMAC-SHA256"
  :req-type "aws4_request"
  :protocol-type "AWS4"
  :hmac-alg :sha256
  :hash-alg :sha256
  :use-uri-encode true
  :remove-empty-segments true
  })

# To create the canonical headers list, convert all header names to
# lowercase and remove leading spaces and trailing spaces. Convert
# sequential spaces in the header value to a single space.
(defn- canonical-headers-entry [value]
  (as-> value ?
  (string/trim ?)
  (peg/replace aws-duplicate-spaces " " ?)
  ))

(defn canonical-headers [headers]
  (default headers {})
  (def sorted-keys (as-> headers ?
      (keys ?)
      (map (fn [k]
        [(string/ascii-lower k) k])
        ?)
      (sort ?)
      ))
  (def signed-headers (buffer))
  (def canonical-form (buffer))
  (loop [[lower header] :in sorted-keys]
    (def value (get headers header))
    (unless (empty? signed-headers)
      (buffer/push signed-headers ";"))
    (buffer/push signed-headers lower)
    (buffer/push canonical-form lower ":")
    (var multi-not-first false)
    # Eliminate duplicate header names by creating one header name
    # with a comma-separated list of values. Be sure there is no
    # whitespace between the values, and be sure that the order of
    # the comma-separated list matches the order that the headers
    # appear in your request. For more information, see RFC 7230
    # section 3.2.
    # https://cloud.google.com/storage/docs/authentication/canonical-requests
    # Append a comma-separated list of values for that header.
    # Do not sort the values in headers that have multiple values.
    # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    (if
      (indexed? value)
      # Do not sort the values
      (loop [multi :in value]
        (if multi-not-first (buffer/push canonical-form ","))
        (buffer/push canonical-form (string/trim multi))
        (set multi-not-first true))
      (buffer/push canonical-form (string/trim value)))
    (buffer/push canonical-form "\n"))
  {
    :canonical-form canonical-form
    :signed-headers signed-headers
  })

(def- needs-uri-encoding-patt (peg/compile '(any (+ (* ($) (if-not (+ :w (set "~-_.")) 1)) 1))))
(defn- needs-uri-encoding [text] (not (empty? (peg/match needs-uri-encoding-patt text))))

(defn- uri-encode-input [input]
  (string/join (map (fn [a]
    (if (< a 16)
      (string/format "%%0%X" a)
      (string/format "%%%X" a)))
      input
      )))

(def- uri-encode-single-equals (peg/compile
  ~(accumulate (any (choice
    # Replace any non A-Za-z0-9~-_. with the uri-encode-input function
    (replace
      (capture (if-not (+ :w (set "~-_.")) 1))
      ,uri-encode-input)
    (capture 1))))))

(def- uri-encode-double-equals (peg/compile
  ~(accumulate (any (choice (replace
    (capture (if-not (+ :w (set "~-_.")) 1))
    ,(fn [input]
      (if (= input "=")
        "%253D"
        (uri-encode-input input)))
    ) (capture 1))))))

(defn uri-encode [text & double-encode-equals]
  (if (needs-uri-encoding text)
    (string/join (if double-encode-equals
      (peg/match uri-encode-double-equals text)
      (peg/match uri-encode-single-equals text)
      ) "")
    text))

(defn canonical-query [queries]
  (default queries {})
  (def canonical-form (buffer))
  (loop [query :in (sort (keys queries))]
    (def value (get queries query))
    (unless (empty? canonical-form)
      (buffer/push canonical-form "&"))
    (if
      (indexed? value)
      (loop [multi :in (sort (array/concat @[] value))]
        (unless (empty? canonical-form)
          (buffer/push canonical-form "&"))
        (buffer/push canonical-form (uri-encode query))
        (buffer/push canonical-form "=")
        (buffer/push canonical-form (uri-encode (string/trim multi) true))
        )
      (do
        (buffer/push canonical-form (uri-encode query))
        (buffer/push canonical-form "=")
        (buffer/push canonical-form (uri-encode (string/trim value) true)))
    ))
    canonical-form)

(defn canonical-uri [uri-input &opt use-uri-encode remove-empty-segments]
  (default use-uri-encode true)
  (default remove-empty-segments true)
  (default uri-input "/")
  (var uri (string uri-input))
  (var last-part-empty false)
  (def parts @[])
  (def segments (string/split "/" uri))
  # (eprintf "Input %p\nSegments %p" uri segments)
  (loop [part :in segments]
    # Examine each segment, if we have "" "" which signifies //
    # and we are to remove empty segments, meaning it becomes /
    # Then skip subsequent empty entries.
    # When uri-encoding is required, apply it.
    (unless (and remove-empty-segments last-part-empty (= "" part))
      (cond
        (= part "..") (array/pop parts)
        (= part "") (array/push parts "")
        use-uri-encode (array/push parts (uri-encode part))
        (array/push parts part)
      )
      (set last-part-empty (= part ""))
    ))

  # Return the canonical uri
  (def result (string "/" (string/join parts "/")))
  # (eprintf "Parts %p\nResult %p" parts result)
  result)

(defn aws-request [{:method method :uri uri :headers headers :body body :query query} &opt opts]
  (default body "")
  (default method :get)
  (default uri "/")
  (default query @{})
  (default opts default-options)

  (def request (buffer))
  (buffer/push request (string/ascii-upper method))
  (buffer/push request "\n")
  (buffer/push request (canonical-uri uri (get opts :use-uri-encode) (get opts :remove-empty-segments)))
  (buffer/push request "\n")
  (buffer/push request (canonical-query query))
  (buffer/push request "\n")
  (def {
    :canonical-form canonical-headers-value
    :signed-headers signed-headers} (canonical-headers headers))
  (buffer/push request canonical-headers-value)
  (buffer/push request "\n")
  (buffer/push request signed-headers)
  (buffer/push request "\n")
  (buffer/push request (md/digest :sha256 body :hex))
  {
    :canonical-request request
    :signed-headers signed-headers
  })

(defn hash-aws-request [request &opt opts]
  (def req (aws-request request opts))
  (default opts default-options)
  (merge req {
    :hash (md/digest (get opts :hash-alg :sha256) (get req :canonical-request) :hex)
  }))

(defn credential-scope [date region service &opt req-type]
  (default req-type "aws4_request")
  (buffer (string/slice date 0 8) "/" region "/" service "/" req-type))

(defn sign-string [date region service hash &opt alg req-type]
  (default alg "AWS4-HMAC-SHA256")
  (default req-type "aws4_request")
  (def scope (credential-scope date region service req-type))
  {
    :scope scope
    :string-to-sign (buffer alg "\n" date "\n" scope "\n" hash)
  })

(defn find-date [request]
  (var date nil)
  (set date (get-in request [:headers "X-Amz-Date"]))
  (if (nil? date) (set date (get-in request [:headers "x-amz-date"])))
  (if (nil? date) (set date (get-in request [:headers "Date"])))
  (if (nil? date) (set date (get-in request [:headers "date"])))
  (if (nil? date) (set date (get-in request [:query "X-Amz-Date"])))
  date
  )

(defn sign-request [secret-key region service request &opt opts]
  (def date (find-date request))
  (unless date
    (error "X-Amz-Date or Date must be present as a header, or X-Amz-Date must be present as a query parameter"))
  (default opts default-options)
  (def sig-key (signature-key
    secret-key
    (string/slice date 0 8)
    region
    service
    (get opts :req-type)
    (get opts :protocol-type)))
  (def {
    :hash hashed-request
    :signed-headers signed-headers
    } (hash-aws-request request opts))
  (def {
    :string-to-sign string-to-sign
    :scope scope
    } (sign-string
    date region service hashed-request
    (get opts :alg)
    (get opts :req-type)))
  {
    :signature (md/hmac (get opts :hmac-alg) sig-key string-to-sign :hex)
    :signed-headers signed-headers
    :scope scope
    :date date
  })

(defn credential [access-key scope] (string access-key "/" scope))

(defn authorization-header [access-key secret-key region service request &opt opts]
  (default opts default-options)
  (def {
    :signature signature
    :signed-headers signed-headers
    :scope scope
  } (sign-request secret-key region service request opts))
  (buffer
    (get opts :alg)
    " Credential=" (credential access-key scope)
    ", SignedHeaders=" signed-headers
    ", Signature=" signature))

(defn iso8601-basic [&opt time]
  (def {:year year :month month :month-day day :hours hour :minutes minute :seconds second} (os/date (or time (os/time))))
  (buffer
    year
    (if (< 10 month) "0") month
    (if (< 10 day) "0") day
    "T"
    (if (< 10 hour) "0") hour
    (if (< 10 minute) "0") minute
    (if (< 10 second) "0") second
    "Z"
    ))

(def- iso8601-basic-parser (peg/compile '(sequence
    (capture (repeat 4 :d))
    (capture (repeat 2 :d))
    (capture (repeat 2 :d))
    "T"
    (capture (repeat 2 :d))
    (capture (repeat 2 :d))
    (capture (repeat 2 :d))
    "Z")))

(defn parse-iso8601-basic [text]
  (if-let [
    segments (peg/match iso8601-basic-parser text)
    numbers (map scan-number segments)
  ] {
    :year (get numbers 0)
    :month (get numbers 1)
    :month-day (get numbers 2)
    :hours (get numbers 3)
    :minutes (get numbers 4)
    :seconds (get numbers 5)
   }))

(defn query-parameters [access-key secret-key region service request &opt opts]
  (default opts default-options)
  (def request (merge @{} request))
  (def query (merge @{} (get request :query {})))
  (var date (get query "X-Amz-Date"))
  (unless date (set date (iso8601-basic (get opts :date))))
  (def scope (credential-scope date region service (get opts :req-type)))
  (put query "X-Amz-Algorithm" (get opts :alg))
  (put query "X-Amz-Credential" (credential access-key scope))
  (put query "X-Amz-Date" date)
  (def signed-headers (as-> (get request :headers {}) ?
      (keys ?)
      (map string/ascii-lower ?)
      (sort ?)
      (string/join ? ";")
      ))
  (put query "X-Amz-SignedHeaders" signed-headers)
  (when (> (get opts :expires-in-seconds 0) 0)
    (put query "X-Amz-Expires" (string (get opts :expires-in-seconds 0))))
  (put request :query query)
  (def {
    :signature signature
  } (sign-request secret-key region service request opts))
  (put query "X-Amz-Signature" signature)
  query)

(def- sigv4-authorization-parser (peg/compile '(sequence
  (capture (some (if-not :s 1)))
  " Credential="
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some :d))
  "/"
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some (if-not (choice :s ",") 1)))
  ", SignedHeaders="
  (capture (some (if-not (choice :s ",") 1)))
  ", Signature="
  (capture (some :h))
  )))

(defn parse-sigv4-authorization [text]
  (default text "")
  (def result (peg/match sigv4-authorization-parser text))
  (if result
    {
      :alg (get result 0)
      :access-key-id (get result 1)
      :date-iso8601 (get result 2)
      :region (get result 3)
      :service (get result 4)
      :req-type (get result 5)
      :signed-headers (string/split ";" (get result 6))
      :signature (get result 7)
    }))

(def sigv4-credential-parser (peg/compile '(sequence
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some :d))
  "/"
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some (if-not (choice :s "," "/") 1)))
  "/"
  (capture (some (if-not (choice :s ",") 1)))
  )))

(defn parse-sigv4-credential [text]
  (default text "")
  (def result (peg/match sigv4-credential-parser text))
  (if result
    {
      :access-key-id (get result 0)
      :date-iso8601 (get result 1)
      :region (get result 2)
      :service (get result 3)
      :req-type (get result 4)
    }))

(defn inspect-request [request]
  (def request-date (or
    (get-in request [:headers "X-Amz-Date"])
    (get-in request [:headers "x-amz-date"])
    (get-in request [:headers "Date"])
    (get-in request [:headers "date"])
    (get-in request [:query "X-Amz-Date"])
    ))
  (unless request-date (error "Request date could not be found"))
  (def request-expires (or
    (get-in request [:headers "X-Amz-Expires"])
    (get-in request [:headers "x-amz-Expires"])
    (get-in request [:query "X-Amz-Expires"])
    ))
  (def request-authorization (or
    (get-in request [:headers "Authorization"])
    (get-in request [:headers "authorization"])
    ))
  (def request-alg (get-in request [:query "X-Amz-Algorithm"]))
  (def request-signed-headers (get-in request [:query "X-Amz-SignedHeaders"]))
  (def request-signature (get-in request [:query "X-Amz-Signature"]))
  (def request-credential (get-in request [:query "X-Amz-Credential"]))
  # Algorithm, SignedHeaders, Signature, and Credential is a query
  # parameter only thing. I think SignedHeaders is optional.
  # Combined they replace the Authorization header.
  (unless (or request-authorization (and request-alg request-signed-headers request-signature request-credential))
    (error "(Authorization header) or (Algorithm and SignedHeaders and Signature and Credential query) missing"))
  # Finally get to the logic
  (def headers @{})
  (def queries @{})
  (var signed-headers @[])
  (var alg nil)
  (var access-key-id nil)
  (var region nil)
  (var service nil)
  (var req-type nil)
  (var date-iso8601 nil)
  (var signature nil)

  (when request-authorization
    (def result (parse-sigv4-authorization request-authorization))
    (unless result (error "Authorization did not match Signature Version 4 format"))
    (set alg (get result :alg))
    (set access-key-id (get result :access-key-id))
    (set region (get result :region))
    (set service (get result :service))
    (set req-type (get result :req-type))
    (set date-iso8601 (get result :date-iso8601))
    (set signature (get result :signature))
    (set signed-headers (get result :signed-headers))
    )
  (unless request-authorization
    (when request-alg
      (set alg request-alg))
    (when request-credential
      (def result (parse-sigv4-credential request-credential))
      (unless result (error "Authorization did not match Signature Version 4 format"))
      (set access-key-id (get result :access-key-id))
      (set region (get result :region))
      (set service (get result :service))
      (set req-type (get result :req-type))
      (set date-iso8601 (get result :date-iso8601)))
    (when request-signature
      (set signature request-signature))
    (when request-signed-headers
      (set signed-headers (string/split ";" request-signed-headers))))

  (unless alg (error "Algorithm could not be found"))
  (unless access-key-id (error "Access Key ID could not be found"))
  (unless region (error "Region could not be found"))
  (unless req-type (error "Request Type (e.g. aws4_request) could not be found"))
  (unless service (error "Service could not be found"))
  (unless date-iso8601 (error "Credential Scope Date could not be found"))
  (unless signature (error "Signature could not be found"))

  # The reduced request should only contain headers identified as signed
  (def included-headers @{})
  (loop [signed :in signed-headers]
    (put included-headers signed true))
  # Include only the headers which are signed
  (def request-headers (get request :headers))
  (loop [header :in (keys request-headers)]
    (when (get included-headers (string/ascii-lower header))
      (put headers header (get request-headers header))))

  # Add all queries except for the signature
  (loop [query :in (keys (get request :query))]
    (unless (= "X-Amz-Signature" query)
      (put queries query (get-in request [:query query]))))
  # Return the reduced request with all the other information
  # inspected from the request
  {
    :request @{
      :headers headers
      :query queries
      :method (get request :method "GET")
      :uri (get request :uri "/")
      :body (get request :body)
      }
    :alg alg
    :access-key-id access-key-id
    :date-scope date-iso8601
    :region region
    :service service
    :req-type req-type
    :signed-headers signed-headers
    :signature signature
    :date request-date
    :expires request-expires
  })

(defn verify-request [secret-key inspected-request &opt opts]
  (default opts default-options)
  (def date (get opts :date (os/time)))
  (def expires (or
    (get inspected-request :expires)
    (get opts :expires)
    86400
    ))
  (def request-date-text (get inspected-request :date))
  (def request-date-scope (get inspected-request :date-scope))
  (unless (= (slice request-date-text 0 8) request-date-scope)
    (error "Date differs between scope and request headers/queries"))
  (def request-date (parse-iso8601-basic request-date-text))
  (unless request-date
    (error "Request date did not match ISO 8601 Basic form"))
  (def request-date (os/mktime request-date))
  (def request-expires (+ request-date expires))
  (when (< request-expires date)
    (error "The request has expired"))

  (def request (get inspected-request :request))
  (def region (get inspected-request :region))
  (def service (get inspected-request :service))
  (def signed-request (sign-request secret-key region service request opts))
  (def signature (get signed-request :signature))
  # Use hex decode in case there's a differing upper/lower casing
  (constant=
    (hex/decode signature)
    (hex/decode (get inspected-request :signature))
    ))
