package ip

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	endpoint = "https://freeipapi.com/api/json"
)

type freeApiIpResponse struct {
	IpVersion   int     `json:"ipVersion,omitempty"`
	IpAddress   string  `json:"ipAddress,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	CountryName string  `json:"countryName,omitempty"`
	CountryCode string  `json:"countryCode,omitempty"`
	Timezone    string  `json:"timeZone,omitempty"`
	ZipCode     string  `json:"zipCode,omitempty"`
	CityName    string  `json:"cityName,omitempty"`
	RegionName  string  `json:"regionName,omitempty"`
}

type FreeIpApiProvider struct {
	client http.Client
}

func NewFreeIpApiProvider() *FreeIpApiProvider {
	return &FreeIpApiProvider{
		client: http.Client{Timeout: 5 * time.Second},
	}
}

func (p *FreeIpApiProvider) GetLocation(ip string) string {
	response, err := p.getIpInfo(ip)
	if err != nil {
		return ""
	}
	return p.createLocationStr(*response)
}

func (p *FreeIpApiProvider) getIpInfo(ip string) (*freeApiIpResponse, error) {
	res, err := p.client.Get(fmt.Sprintf("%s/%s", endpoint, ip))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New("error Free IP API server response")
	}
	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var response freeApiIpResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (p *FreeIpApiProvider) createLocationStr(info freeApiIpResponse) string {
	location := ""
	p.addFormattedLocationInfo(&location, info.CityName)
	p.addFormattedLocationInfo(&location, info.RegionName)
	p.addFormattedLocationInfo(&location, info.CountryName)
	return location
}

func (p *FreeIpApiProvider) addFormattedLocationInfo(str *string, info string) {
	if len(info) > 0 {
		if len(*str) > 0 {
			*str += ", "
		}
		*str += info
	}
}
