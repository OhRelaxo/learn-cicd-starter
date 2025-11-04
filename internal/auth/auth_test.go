package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAuth(t *testing.T) {
	tests := map[string]struct {
		key        string
		value      string
		want       string
		wantErr    error
		wantErrMsg string
	}{
		"simple": {
			key:     "Authorization",
			value:   "ApiKey 1234567890",
			want:    "1234567890",
			wantErr: nil,
		},
		"noApiKey": {
			key:     "Authorization",
			value:   "",
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed_no_scheme": {
			key:        "Authorization",
			value:      "1234567890",
			want:       "",
			wantErrMsg: "malformed authorization header",
		},
		"wrong_scheme": {
			key:        "Authorization",
			value:      "Bearer 123456",
			want:       "",
			wantErrMsg: "malformed authorization header",
		},
		"multiple_spaces": {
			key:   "Authorization",
			value: "ApiKey    123456",
			// current implementation splits on " " and takes index 1 -> empty string
			want:    "",
			wantErr: nil,
		},
		"extra_parts": {
			key:   "Authorization",
			value: "ApiKey 123 extra",
			// function returns splitAuth[1] ("123") and ignores extras
			want:    "123",
			wantErr: nil,
		},
		"trailing_space": {
			key:   "Authorization",
			value: "ApiKey ",
			want:  "",
			// split yields ["ApiKey", ""] -> no error, empty key
			wantErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			header.Set(tc.key, tc.value)
			got, err := GetAPIKey(header)

			// error expectations
			if tc.wantErr == nil && tc.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.wantErr != nil {
					if err != tc.wantErr {
						t.Fatalf("expected error %v, got %v", tc.wantErr, err)
					}
				}
				if tc.wantErrMsg != "" {
					if err.Error() != tc.wantErrMsg {
						t.Fatalf("expected error message %q, got %q", tc.wantErrMsg, err.Error())
					}
				}
			}

			// only compare result when no error was returned
			if err == nil {
				if diff := cmp.Diff(tc.want, got); diff != "" {
					t.Fatalf("unexpected result (-want +got):\n%s", diff)
				}
			}
		})
	}
}
