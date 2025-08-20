// this package parses html responses from https://bgp.he.net/, i hate parsing
package bgp

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const hosturl = "https://bgp.he.net/"

func Subnet(ip net.IP) (*net.IPNet, error) {
	path, err := url.JoinPath(hosturl, "ip", ip.String())
	if err != nil {
		panic(err)
	}

	res, err := http.Get(path)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("non-200 status code: %v %v", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		panic(err) // shouldn't happen? idk
	}

	href, exists := doc.Find("td.nowrap > a").Attr("href")
	if !exists {
		panic("shouldn't happen, please report")
	}

	href = strings.Trim(strings.Replace(href, "/net/", "", -1), "/")

	_, cidr, err := net.ParseCIDR(href)
	if err != nil {
		return nil, err
	}

	return cidr, nil
}

func Domains(subnet *net.IPNet) ([]string, error) {
	path, err := url.JoinPath(hosturl, "net", subnet.String())
	if err != nil {
		panic(err)
	}

	res, err := http.Get(path)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("non-200 status code: %v %v", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		panic(err)
	}

	domains := []string{}

	doc.Find("#dnsrecords > table > tbody > tr > td:nth-child(3) > a").Each(func(i int, s *goquery.Selection) {
		domains = append(domains, s.Text())
	})

	return domains, nil
}
