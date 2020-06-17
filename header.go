package bearer_auth

import "fmt"

func AppendBearer(token string) string {
	return fmt.Sprintf("%s%s", BEARER_PREFIX, token)
}
