package main

type securityFile struct {
	LatestPluginVersion string                `json:"latestPluginVersion"`
	Advisories          map[string]advisories `json:"advisories"`
	VersionToAdvisories map[string][]string   `json:"versionToAdvisories"`
}

type advisories struct {
	Title      string `json:"title"`
	Link       string `json:"link"`
	CVE        string `json:"cve"`
	Affected   string `json:"affectedVersions"`
	Source     string `json:"source"`
	ReportedAt string `json:"reportedAt"`
}
