package proxy

// LabeledRange represents a subnet range with a geographic/provider label.
type LabeledRange struct {
	Cidr            string `json:"cidr"`
	Label           string `json:"label"`
	DefaultSelected bool   `json:"default_selected"`
}

// CDNPreset represents a pre-configured CDN range list for scanning or spoofing.
type CDNPreset struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Snis   []string       `json:"snis"`
	Ranges []LabeledRange `json:"ranges"`
}

// DoHPreset represents a pre-configured secure DNS-over-HTTPS resolver.
type DoHPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// GetCDNPresets returns the preset configurations compiled from field operations (including Iran-specific ISP targets).
func GetCDNPresets() []CDNPreset {
	return []CDNPreset{
		{
			ID:   "cloudflare",
			Name: "Cloudflare",
			Snis: []string{
				"www.cloudflare.com",
				"discord.com",
				"www.cloudflareapps.com",
				"cdnjs.cloudflare.com",
				"www.shopify.com",
				"www.medium.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "162.159.192.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "162.159.193.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "162.159.195.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.96.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.97.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.98.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.99.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "104.16.0.0/13", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "104.24.0.0/14", Label: "Cloudflare", DefaultSelected: true},
			},
		},
		{
			ID:   "fastly",
			Name: "Fastly",
			Snis: []string{
				"www.fastly.com",
				"www.reddit.com",
				"www.nytimes.com",
				"www.imgur.com",
				"www.spotify.com",
				"developer.mozilla.org",
			},
			Ranges: []LabeledRange{
				{Cidr: "151.101.0.0/16", Label: "Fastly", DefaultSelected: true},
				{Cidr: "199.232.0.0/16", Label: "Fastly", DefaultSelected: true},
			},
		},
		{
			ID:   "google",
			Name: "Google CDN",
			Snis: []string{
				"fonts.googleapis.com",
				"ajax.googleapis.com",
				"storage.googleapis.com",
				"www.gstatic.com",
				"ssl.gstatic.com",
				"accounts.google.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "34.143.0.0/24", Label: "Cloud Run", DefaultSelected: true},
				{Cidr: "34.160.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "34.96.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "35.186.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "64.233.160.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "66.249.80.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "74.125.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "142.250.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "172.217.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "216.58.192.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "35.201.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "34.117.0.0/24", Label: "Cloud", DefaultSelected: true},
			},
		},
		{
			ID:   "amazon",
			Name: "Amazon CloudFront",
			Snis: []string{
				"d1.cloudfront.net",
				"d2.cloudfront.net",
				"d3.cloudfront.net",
				"aws.cloudfront.net",
				"s3.amazonaws.com",
				"edge.cloudfront.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "13.32.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "13.35.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "52.46.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "54.192.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "54.230.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "99.84.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "130.176.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "143.204.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "205.251.192.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "54.239.128.0/24", Label: "Global", DefaultSelected: true},
			},
		},
		{
			ID:   "azure",
			Name: "Microsoft Azure",
			Snis: []string{
				"ajax.aspnetcdn.com",
				"az416426.vo.msecnd.net",
				"az784690.vo.msecnd.net",
				"cdn.office.net",
				"static.azureedge.net",
				"az.msecnd.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "13.107.4.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "23.96.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "40.64.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "52.224.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "104.208.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "137.116.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "168.61.0.0/24", Label: "US", DefaultSelected: true},
			},
		},
		{
			ID:   "iran-isp",
			Name: "Iran ISP Pre-tested (MCI / Irancell / Rightel / Shatel / Asiatech / Pars)",
			Snis: []string{
				"a248.e.akamai.net",
				"a77.net.akamai.net",
				"a104.net.akamai.net",
				"a184.net.akamai.net",
				"ds-aksb.akamaized.net",
				"ak.net.akamaized.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "184.24.77.42/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "184.24.77.32/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "185.200.232.49/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "23.48.23.151/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "104.112.146.82/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "184.24.77.7/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "2.22.250.149/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "23.58.193.140/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "184.24.77.5/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "185.200.232.50/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "23.43.237.239/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "92.16.53.11/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "184.24.77.21/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "185.200.232.42/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "23.48.23.186/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "72.246.28.3/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "92.122.0.1/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "184.24.77.11/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "185.200.232.41/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "23.48.23.133/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "2.19.126.81/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "104.64.0.5/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "184.24.77.16/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "185.200.232.43/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "23.48.23.195/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "104.64.0.6/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "184.24.77.36/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "185.200.232.8/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "23.48.23.178/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "104.64.0.7/32", Label: "ParsOnline", DefaultSelected: true},
			},
		},
		{
			ID:   "warp",
			Name: "Cloudflare WARP",
			Snis: []string{
				"engage.cloudflareclient.com",
				"private-charter.cloudflareclient.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "8.6.112.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.34.70.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.34.146.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.35.211.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.125.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.204.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.214.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.47.69.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "162.159.192.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "162.159.195.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.96.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.97.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.98.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.99.0/24", Label: "WARP", DefaultSelected: true},
			},
		},
		{
			ID:   "akamai",
			Name: "Akamai CDN",
			Snis: []string{
				"a248.e.akamai.net",
				"a77.net.akamai.net",
				"a104.net.akamai.net",
				"a184.net.akamai.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.16.0.0/13", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.0.0.0/12", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.32.0.0/11", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.64.0.0/14", Label: "Akamai", DefaultSelected: true},
				{Cidr: "69.192.0.0/16", Label: "Akamai", DefaultSelected: true},
				{Cidr: "72.246.0.0/15", Label: "Akamai", DefaultSelected: true},
				{Cidr: "88.221.0.0/16", Label: "Akamai", DefaultSelected: true},
				{Cidr: "104.64.0.0/10", Label: "Akamai", DefaultSelected: true},
				{Cidr: "184.24.0.0/13", Label: "Akamai", DefaultSelected: true},
				{Cidr: "184.84.0.0/14", Label: "Akamai", DefaultSelected: true},
			},
		},
		{
			ID:   "arvancloud",
			Name: "Arvan Cloud",
			Snis: []string{
				"www.arvancloud.ir",
				"rdisk.arvancloud.ir",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.144.3.128/28", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.16.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.17.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.18.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.19.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "94.101.182.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "178.131.120.48/28", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "185.143.232.0/22", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "185.215.232.0/22", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "188.229.116.16/30", Label: "ArvanCloud", DefaultSelected: true},
			},
		},
		{
			ID:   "derakcloud",
			Name: "Derak Cloud",
			Snis: []string{
				"derak.cloud",
				"panel.derak.cloud",
			},
			Ranges: []LabeledRange{
				{Cidr: "5.145.115.0/24", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "5.145.118.0/23", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "45.63.43.128/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "45.77.87.48/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "89.222.113.80/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "116.202.90.176/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "159.69.229.224/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "165.232.92.112/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "178.62.222.208/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.252.192/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.254.64/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.255.192/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.255.224/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "192.168.204.48/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "207.148.25.64/28", Label: "DerakCloud", DefaultSelected: true},
			},
		},
		{
			ID:   "netlify",
			Name: "Netlify",
			Snis: []string{
				"netlify.com",
				"www.netlify.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "3.33.128.0/17", Label: "Netlify", DefaultSelected: true},
				{Cidr: "13.32.0.0/15", Label: "Netlify", DefaultSelected: true},
				{Cidr: "13.35.0.0/16", Label: "Netlify", DefaultSelected: true},
				{Cidr: "18.64.0.0/14", Label: "Netlify", DefaultSelected: true},
				{Cidr: "44.226.105.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.4.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.85.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.87.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "44.235.184.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "52.84.0.0/15", Label: "Netlify", DefaultSelected: true},
				{Cidr: "35.157.26.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "63.176.8.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "54.182.0.0/16", Label: "Netlify", DefaultSelected: true},
				{Cidr: "99.83.128.0/17", Label: "Netlify", DefaultSelected: true},
				{Cidr: "162.159.128.0/20", Label: "Netlify", DefaultSelected: true},
			},
		},
		{
			ID:   "vercel",
			Name: "Vercel",
			Snis: []string{
				"vercel.com",
				"www.vercel.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "64.29.17.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "64.29.18.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "64.29.19.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "66.33.60.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "66.33.61.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "76.76.21.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "76.223.126.0/24", Label: "Vercel", DefaultSelected: true},
			},
		},
		{
			ID:   "bunnycdn",
			Name: "BunnyCDN",
			Snis: []string{
				"bunny.net",
				"bunnycdn.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "89.187.160.0/19", Label: "BunnyCDN", DefaultSelected: true},
				{Cidr: "147.75.0.0/16", Label: "BunnyCDN", DefaultSelected: true},
			},
		},
		{
			ID:   "gcore",
			Name: "Gcore",
			Snis: []string{
				"gcore.com",
				"gcorelabs.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "92.223.0.0/16", Label: "Gcore", DefaultSelected: true},
				{Cidr: "95.85.0.0/16", Label: "Gcore", DefaultSelected: true},
				{Cidr: "185.158.0.0/16", Label: "Gcore", DefaultSelected: true},
			},
		},
		{
			ID:   "iranserver",
			Name: "IranServer CDN",
			Snis: []string{
				"iranserver.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "5.182.45.23/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "5.182.45.37/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "45.159.114.11/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "87.98.249.55/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "93.127.182.21/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "93.127.182.24/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.143.229.14/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.182.97.44/31", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.182.97.46/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "168.119.4.117/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "185.116.162.15/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "185.116.162.19/32", Label: "IranServer", DefaultSelected: true},
			},
		},
		{
			ID:   "parspack",
			Name: "ParsPack CDN",
			Snis: []string{
				"parspack.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.144.23.191/32", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "5.135.72.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "5.160.143.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "31.214.248.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.32.131.160/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.32.154.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.76.132.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.211.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.211.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.223.80/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.139.11.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "46.20.41.224/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "64.176.15.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "64.176.64.80/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "65.20.72.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "65.20.113.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "77.237.66.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "79.175.148.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "84.17.42.224/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "87.236.161.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "89.36.162.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "89.187.169.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "91.228.186.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "94.182.153.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.140.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.164.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.220.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.254.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.188.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.219.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.240.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.250.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "130.185.74.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "130.185.79.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "139.84.177.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "139.84.236.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.58.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.78.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.114.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "155.138.162.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "158.51.122.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "158.247.223.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "167.179.93.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "171.22.26.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "178.22.120.192/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.173.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.174.144/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.175.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.110.191.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.204.197.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.208.175.144/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "194.5.188.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.88.208.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.181.174.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.248.241.160/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.248.242.192/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "199.247.3.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "207.148.69.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "208.85.22.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "213.183.48.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "216.238.117.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "217.197.97.48/28", Label: "ParsPack", DefaultSelected: true},
			},
		},
	}
}

// GetWarpPorts returns the list of candidate WARP ports from the field logs.
func GetWarpPorts() []int {
	return []int{
		500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
		955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
		2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
		7559, 8319, 8742, 8854, 8886,
	}
}

// GetDoHPresets returns the list of popular secure DoH resolvers.
func GetDoHPresets() []DoHPreset {
	return []DoHPreset{
		{ID: "cloudflare", Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Description: "Fast, privacy-focused secure DNS"},
		{ID: "cloudflare-security", Name: "Cloudflare (Security)", URL: "https://security.cloudflare-dns.com/dns-query", Description: "Blocks malware domains"},
		{ID: "google", Name: "Google Public DNS", URL: "https://dns.google/dns-query", Description: "Highly reliable global resolver"},
		{ID: "adguard", Name: "AdGuard DNS (Default)", URL: "https://dns.adguard-dns.com/dns-query", Description: "Blocks ads, trackers, and phishing"},
		{ID: "adguard-unfiltered", Name: "AdGuard DNS (Unfiltered)", URL: "https://unfiltered.adguard-dns.com/dns-query", Description: "Uncensored DNS, no ad-blocking"},
		{ID: "quad9", Name: "Quad9", URL: "https://dns.quad9.net/dns-query", Description: "High-performance security-focused DNS"},
		{ID: "controld-unfiltered", Name: "Control D (Unfiltered)", URL: "https://freedns.controld.com/p0", Description: "Fast anycast DNS, no blocking"},
		{ID: "controld-ads", Name: "Control D (Ads & Trackers)", URL: "https://freedns.controld.com/p2", Description: "Blocks ads, tracking, and malware"},
		{ID: "dns-sb", Name: "DNS.SB", URL: "https://doh.dns.sb/dns-query", Description: "Privacy-focused, no logging"},
		{ID: "sarak-doh", Name: "Sarak DoH", URL: "https://dns.sarak.as/dns-query", Description: "Custom secure DNS-over-HTTPS resolver"},
	}
}

// DNSPreset represents a standard IPv4/IPv6 DNS resolver preset (e.g. for gaming or anti-sanction).
type DNSPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Primary     string   `json:"primary"`
	Secondary   string   `json:"secondary"`
	Description string   `json:"description"`
}

// GetDNSPresets returns the list of popular DNS resolvers, including gaming/anti-sanction presets from Iran (Radar, Zeus, Shecan, etc.).
func GetDNSPresets() []DNSPreset {
	return []DNSPreset{
		{ID: "radar", Name: "Radar Game", Primary: "10.202.10.10", Secondary: "10.202.10.11", Description: "Iran gaming and anti-sanction DNS"},
		{ID: "zeus", Name: "Zeus", Primary: "37.32.5.60", Secondary: "37.32.5.61", Description: "Iran anti-sanction bypass DNS"},
		{ID: "vanilla", Name: "Vanilla", Primary: "10.139.177.21", Secondary: "10.139.177.22", Description: "Iran alternative bypass DNS"},
		{ID: "shecan", Name: "Shecan", Primary: "178.22.122.100", Secondary: "185.51.200.25", Description: "Popular Iran bypass DNS for sanctions"},
		{ID: "begzar", Name: "Begzar", Primary: "185.55.226.26", Secondary: "185.55.225.25", Description: "Anti-censorship and bypass DNS"},
		{ID: "electro", Name: "Electro", Primary: "78.157.42.100", Secondary: "78.157.42.101", Description: "Iran gaming radar and service bypass"},
		{ID: "google", Name: "Google DNS", Primary: "8.8.8.8", Secondary: "8.8.4.4", Description: "Google public DNS"},
		{ID: "cloudflare", Name: "Cloudflare DNS", Primary: "1.1.1.1", Secondary: "1.0.0.1", Description: "Cloudflare public DNS"},
	}
}

// ScanPreset represents a scanner configuration profile.
type ScanPreset struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Concurrency         int      `json:"concurrency"`
	TimeoutMS           int      `json:"timeout_ms"`
	EnableTcp           bool     `json:"enable_tcp"`
	EnableTls           bool     `json:"enable_tls"`
	EnableHttp          bool     `json:"enable_http"`
	EnableTunnel        bool     `json:"enable_tunnel"`
	AdaptiveTimeout     bool     `json:"adaptive_timeout"`
	ConfirmationRequire bool     `json:"confirmation_require"`
}

// GetScanPresets returns the recommended scanner presets.
func GetScanPresets() []ScanPreset {
	return []ScanPreset{
		{
			ID:                  "safe_quick",
			Name:                "Safe Quick",
			Description:         "Conservative visible default, moderate concurrency/rate/jitter, no privileged mutation, explicit targets first.",
			Concurrency:         64,
			TimeoutMS:           2000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          false,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "diagnostic",
			Name:                "Diagnostic",
			Description:         "Local diagnostics and optional public-IP check with clear disclosure of external services contacted.",
			Concurrency:         16,
			TimeoutMS:           4000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "provider_sample",
			Name:                "Provider Sample",
			Description:         "Bounded provider/corpus sample with requested budget, route/resolver policy, and attribution evidence.",
			Concurrency:         32,
			TimeoutMS:           4000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "deep_manual",
			Name:                "Deep Manual",
			Description:         "User-confirmed broader scan with visible warnings, estimated duration/data/battery impact, and rate caps.",
			Concurrency:         128,
			TimeoutMS:           5000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        true,
			AdaptiveTimeout:     true,
			ConfirmationRequire: true,
		},
		{
			ID:                  "advanced_transport",
			Name:                "Advanced Transport",
			Description:         "Explicit advanced transport mode, disabled by default, requiring consent, route evidence, provenance, and legal gates.",
			Concurrency:         256,
			TimeoutMS:           5000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        true,
			AdaptiveTimeout:     true,
			ConfirmationRequire: true,
		},
	}
}

// EvasionISPPreset represents the evasion calibration parameters for a specific ISP (MCI, Irancell, TCI).
type EvasionISPPreset struct {
	ISP           string  `json:"isp"`
	NumFragment   int     `json:"num_fragment"`
	FragmentSleep float64 `json:"fragment_sleep"`
	SocketTimeout int     `json:"socket_timeout"`
}

// GetEvasionISPPresets returns the calibration settings ported from MahsaNG.
func GetEvasionISPPresets() []EvasionISPPreset {
	return []EvasionISPPreset{
		{ISP: "mci", NumFragment: 150, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "irancell", NumFragment: 14, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "tci", NumFragment: 200, FragmentSleep: 0.003, SocketTimeout: 8},
		{ISP: "any", NumFragment: 100, FragmentSleep: 0.008, SocketTimeout: 8},
	}
}

