// Real certificates, for tests/posture.test.ts and tests/postureCertificates.test.ts.
//
// Not a test file: no `describe` here, because importing one test file from
// another registers its cases twice. In its own module so the two suites that
// need these bodies share one copy and cannot drift into disagreeing about
// what date a fixture carries.
//
// Each was minted with
//
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out <f> \
//     -subj "/CN=<name>" -not_before <t> -not_after <t>
//
// so the validity is ABSOLUTE and the expected dates in the tests are literals
// rather than something derived from the parser under test. The bodies are the
// base64 between the PEM armour, which is exactly what the collector transmits.
//
//   CERT_SOON         notAfter 2027-02-01T12:00:00Z, UTCTime
//   CERT_EXPIRED      notAfter 2026-12-20T00:00:00Z, UTCTime, already past
//   CERT_FAR          notAfter 2028-06-01T00:00:00Z, UTCTime
//   CERT_GENERALIZED  notAfter 2050-01-01T00:00:00Z, GeneralizedTime — RFC 5280
//                     requires that encoding for 2050 and later, and a parser
//                     that knew only UTCTime would call an estate's
//                     longest-lived certificates unparseable.

export const CERT_SOON =
  "MIIDFzCCAf+gAwIBAgIUahzv1WT89PsizAMLt+O1HZL3WlIwDQYJKoZIhvcNAQELBQAwGzEZMBcG" +
  "A1UEAwwQc29vbi5leGFtcGxlLmNvbTAeFw0yNzAxMDEwMDAwMDBaFw0yNzAyMDExMjAwMDBaMBsx" +
  "GTAXBgNVBAMMEHNvb24uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" +
  "AQC6Rs8bs5/B9ApvAbvvdog+Xl9HheKpeHaO0siaK6BKA2RBFB6iS0p95OpVwwYLx1tiHQ7B+GDt" +
  "LzqiBRfdTSs62qL+DnOnnIB2+xa292ezJd/seipQ731GbtFfoIFbwkCtaIqfmWZjGhtIz1z9SWuM" +
  "IR55jHdbO/mf5/aPGsYcgCO/dG28j9v1RwSO/MffjJNfi7GjQ+zsX+OXVjiJpWD88PcwJUBZ64kO" +
  "CVKaRcYQTGLxwSh1jIQWqVT/jrHHBZzsSDUCt2K0oEU5Mmg7txoQMCeCTbdFudKTNn9pay7bIdUm" +
  "+fp+jGQE+4TfphJm3HMJwK90vwSQeUZ0/pgzQiqHAgMBAAGjUzBRMB0GA1UdDgQWBBRvkmkY1c81" +
  "rcnKEdulLzDfHTH/aTAfBgNVHSMEGDAWgBRvkmkY1c81rcnKEdulLzDfHTH/aTAPBgNVHRMBAf8E" +
  "BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCTXPYPzWb4GPy38/HK7zUnujLPuuletFzxxD01+cPL" +
  "wpFpdkITDixmjWp0fBeYgy+9XwX0xLoKjx8xs/x2PsO/YFv2M/z/Vplj+shRhhPeyRcLzL5LQ/4F" +
  "LFOrsPb80i6d9EGZVeeDowOwQH1J6PPrBTkERHAn2X/fKPjYNWeo6LtLHw8jfhmxjGdK8KwOaTHh" +
  "t/jgd6wqTElEPvvfOnp6Bb+Kh7Y68QA3+WTeEzIeZWgsDWDO87cdWm4HPZ+Uq06oCK6LEJJH8tn/" +
  "H3HIAw/uSXUyyKJ4bu8YEbdLZ56Hofd1/emPfl6eYWMh4U9m4KnZSNjlerXE9B+10Zcufyuq"

export const CERT_EXPIRED =
  "MIIDHTCCAgWgAwIBAgIURjpbTxj5z3kiNxQAEyjiK1sUfYMwDQYJKoZIhvcNAQELBQAwHjEcMBoG" +
  "A1UEAwwTZXhwaXJlZC5leGFtcGxlLmNvbTAeFw0yNjAxMDEwMDAwMDBaFw0yNjEyMjAwMDAwMDBa" +
  "MB4xHDAaBgNVBAMME2V4cGlyZWQuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw" +
  "ggEKAoIBAQCLdjLLLYA3pZ5HB09EbnTz/uzcEFVvRu/QHhia7vNJLU62VsHiKiQIE7L+gKLbhJBl" +
  "/nQonnId43O8QUEVXc5/xOTQr5bTOTWN28R7ZfSfzM41fcKYAuhw5S0fxJPSpyeMb0Ym6Yiq4+s3" +
  "WVbh3ped5aMXc+IZlBWS3PIU8UgNLxxeC2TQ2yIPMopuyFrE4/kcm6tDpr7zdBeW5DfI+yQCWdQj" +
  "N6ymBz67MkhgqOzvchmUZuh7JL7wU2w+gkKWqo9aW/jVG/jQBff8Og9iO+7x0WDheRGCs3cjEByA" +
  "6Q882RULB4N8lIM7GST/485KvpIxoj3bqwQJhiwE/cPxOVm/AgMBAAGjUzBRMB0GA1UdDgQWBBQW" +
  "R8IDgPuDIXU6lKgmQGzzzy6EjTAfBgNVHSMEGDAWgBQWR8IDgPuDIXU6lKgmQGzzzy6EjTAPBgNV" +
  "HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAUjly1fyg+oQiaX8Rdy6BY2XhcnJa3BDnS" +
  "hzVvH2CMd/cPWcknuGXtQpLcZE9nGJcmMg8LUK5QrumgPo+siLPyGtTP02wY1A+BPkkb6GDp+9Rk" +
  "89EjeCsnI3ua+U+y3CgSISmn+BHL+KHP6I82OGRUPxNaMgB9/iF/bryPH/8Xpftzd44DmaplEEWr" +
  "J14SA4iCgtQO8uwxzNfnFFmXxhdmvcG67JsM3WeKNdN94XIAzN0j7t7QUh8+1RIKD0mXa73DAAHJ" +
  "PF2npT0lcpJgCjxqtojOl1NpizkhxGvAAsqdRvdyh3HeXOc4c+AwPl3NMaapxujFkTkpJTduceLN" +
  "bn+y"

export const CERT_FAR =
  "MIIDFTCCAf2gAwIBAgIUXh0a8ixjgbo2xntHWxi1HDteGYwwDQYJKoZIhvcNAQELBQAwGjEYMBYG" +
  "A1UEAwwPZmFyLmV4YW1wbGUuY29tMB4XDTI3MDEwMTAwMDAwMFoXDTI4MDYwMTAwMDAwMFowGjEY" +
  "MBYGA1UEAwwPZmFyLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
  "q52UCwjar0hFBCzyEv/ty5TSB2dNBX25way9kDsEUnBiEL1+jlG5vXkqdSEDcrigapouj8N0Abf+" +
  "W5L2/NqNChzOTwAU4Sp/XQ6C3wcAuuu1f9TNsL/NAVxsv0EshOyoxlGOBfGVEAbCPcz16wzENXhZ" +
  "Kg4KZ44h9sH4v11d7obUkrmE9DGA2PdZn82086sa+9TKpkZw9vd7urWIDS4F/2Yp24SnuBZ3zo1q" +
  "H+Bc8IGWM5Hnzao8Vl2LNMFxZIZjgIJbXAYImRNpZl9WS50GavDPMwlL1x1zL9uKuw6Et8z/BRUT" +
  "i87pgf3FenqKjy/IVJkxzYAjAe2RGGVFNmvO+QIDAQABo1MwUTAdBgNVHQ4EFgQULdVBipX/hNJG" +
  "rTLnd6Q1zhLLGkUwHwYDVR0jBBgwFoAULdVBipX/hNJGrTLnd6Q1zhLLGkUwDwYDVR0TAQH/BAUw" +
  "AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAhtPaCJxvazle497Nbzq/7y9PJDj74cPuHDaSq4/Mur8i" +
  "n5Rwoa34oeSIlpv12pwSJCSeDOwbHm0y0JrXm6VvyT6/nHXlIM6uIAYGAYsjhTHoaQh2Tx3+Nxhz" +
  "jeE98cn8mTMO5WHAZvns5yB3XhIWlGKXO43Ht/31szJqD89rr6oD3ky28itWwRdigpn5mjWtJg5j" +
  "VWcmpadxdZwejbipKWlI5Jgdvu/OEMd+m2gyJ410b0wx7QiCQpwLUZ2N4mB0pzrpj86hdzX0+/YF" +
  "37oB1fX+bmjpHXX3XF5VsdwpxHn1RpAkdZ+f5WsIOnEDDYKv+F6qQ3ATGvvy5b/Ua5Elbw=="

export const CERT_GENERALIZED =
  "MIIDFzCCAf+gAwIBAgIUapDs/r0UdrRCfpKGYdyw/ipzWOMwDQYJKoZIhvcNAQELBQAwGjEYMBYG" +
  "A1UEAwwPZ2VuLmV4YW1wbGUuY29tMCAXDTI3MDEwMTAwMDAwMFoYDzIwNTAwMTAxMDAwMDAwWjAa" +
  "MRgwFgYDVQQDDA9nZW4uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB" +
  "AQCanMH7HrtWqCOWMx0UZ5OYUWP2LTEHkg/+/IbHcXOEckCtniVUmqJGZms8F1/TJLTHzzJEzxNQ" +
  "bmwobsTqIK8TuK8GKr+5N6lk9rO5OWM0uGXoKWF26UgddFXmmwdfkY8J7xXJODmh460wmIdemk2y" +
  "Ghdzs/JjIJFR9ChGX9fNjScLX2sHEbODW52hKEU+/CwlRQYjT6tJdzxs9Gi95i7xJuOTY9vZMeRS" +
  "Rd7MR2CSvBm9zYl1F/Fmy8SOXNFfAx5RKk7NRAGpryh7zHMwlECYR++5M5e3fAwXSPmBmlXUAp4W" +
  "pz/LN2NG93lZUojKqi1Ta1VDGhEx3hxgidjS5XihAgMBAAGjUzBRMB0GA1UdDgQWBBRjI6d8yQBi" +
  "Z2df4k//6+Cs9Adt2TAfBgNVHSMEGDAWgBRjI6d8yQBiZ2df4k//6+Cs9Adt2TAPBgNVHRMBAf8E" +
  "BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBoL3bK3/+n+lBk5+wbFr9kOC6DRjUOSFhls3JFXSF1" +
  "JSDH1ZCgARV1MONs95nujzflK/JKPvHk3VQkc6Dc1b6O9XmwAAgEALw2bNULrncAWUj+j8n9+s/B" +
  "Grq8IOfnbix43H0FzdFxno4QLGnkJ5eXXhPYx5rfCFybVqZLzFHXU458Wtq6qEID1U9/qcERlnFn" +
  "sRicdaCU1bYrRCXrx7YKFPSQdhPJ6xoibMzS7g1oaJvbBxQs3xSP/Vs00lekf20VcZ1oj+TgNCRI" +
  "gqzG0r2sT+X2o4ooy7h5VKOO+yQbYJCatXJy9K3ZoBf/Bcu514TebQP0J2CrI0ZX1E3G3obs"
