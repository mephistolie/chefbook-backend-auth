package ip

type InfoProvider interface {
	GetLocation(ip string) string
}
