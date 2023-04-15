package query

import "net/url"

func Decode(query string) string {
	decodedQuery, err := url.QueryUnescape(query)
	if err != nil {
		decodedQuery = query
	}
	return decodedQuery
}
