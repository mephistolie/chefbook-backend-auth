package credentials

import "testing"

func TestEmailAddressValidation(t *testing.T) {
	for _, email := range []string{"first.last@example.com", "a+b@example.com"} {
		if ValidateEmail(email) != nil {
			t.Fatalf("valid email %q rejected", email)
		}
	}
	for _, email := range []string{"User <a@example.com>", "a.example.com", "bad@"} {
		if ValidateEmail(email) == nil {
			t.Fatalf("invalid email %q accepted", email)
		}
	}
}
