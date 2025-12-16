package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"

    "github.com/FriendsOfShopware/shopware-cli/version"
    "github.com/google/go-github/v53/github"
)

type advisoryItem struct {
	AdvisoryId         string `json:"advisoryId"`
	PackageName        string `json:"packageName"`
	RemoteId           string `json:"remoteId"`
	Title              string `json:"title"`
	Link               string `json:"link"`
	Cve                string `json:"cve"`
	AffectedVersions   string `json:"affectedVersions"`
	Source             string `json:"source"`
	ReportedAt         string `json:"reportedAt"`
	ComposerRepository string `json:"composerRepository"`
	Sources            []struct {
		Name     string `json:"name"`
		RemoteId string `json:"remoteId"`
	} `json:"sources"`
}

type packagistSecurityResponse struct {
	Advisories struct {
		ShopwarePlatform []advisoryItem `json:"shopware/platform"`
		ShopwareShopware []advisoryItem `json:"shopware/shopware"`
	} `json:"advisories"`
}

func generateSecurityAdvisories(ctx context.Context, tags []*github.RepositoryTag) error {
    packagistAdvisories, err := getAllSecurityAdvisories(ctx)

	if err != nil {
		return err
	}

 latestVersion, err := getSecurityPluginLatestVersion(ctx, "6.4.14.0")

	if err != nil {
		return err
	}

	fileStruct := securityFile{
		LatestPluginVersion:   latestVersion,
		LatestPluginVersionV2: make(map[string]string),
		Advisories:            make(map[string]advisories),
		VersionToAdvisories:   make(map[string][]string),
	}

	for _, v := range []string{"6.7", "6.6", "6.5", "6.4"} {
		latest, err := findLatestVersion(tags, v)
		if err != nil {
			return err
		}

		pluginVer, err := getSecurityPluginLatestVersion(ctx, latest)
		if err != nil {
			return err
		}
		fileStruct.LatestPluginVersionV2[v] = pluginVer
	}

	allAdvisories := append(packagistAdvisories.Advisories.ShopwarePlatform, packagistAdvisories.Advisories.ShopwareShopware...)

	for _, advisory := range allAdvisories {
		fileStruct.Advisories[advisory.AdvisoryId] = advisories{
			Title:      advisory.Title,
			Link:       advisory.Link,
			CVE:        advisory.Cve,
			Affected:   advisory.AffectedVersions,
			Source:     advisory.Source,
			ReportedAt: advisory.ReportedAt,
		}
	}

	for _, tag := range tags {
		v := version.Must(version.NewVersion(tag.GetName()))

		for _, advisory := range allAdvisories {
			processAdvisoryForVersion(advisory.AdvisoryId, advisory.AffectedVersions, v, tag.GetName(), &fileStruct)
		}
	}

	data, err := json.MarshalIndent(fileStruct, "", "  ")

	if err != nil {
		return err
	}

	if err = os.WriteFile("data/security.json", data, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func processAdvisoryForVersion(advisoryId, affectedVersions string, v *version.Version, tagName string, fileStruct *securityFile) {
	constraint := version.MustConstraints(version.NewConstraint(affectedVersions))

	if constraint.Check(v) {
		if fileStruct.VersionToAdvisories[tagName] == nil {
			fileStruct.VersionToAdvisories[tagName] = []string{}
		}

		fileStruct.VersionToAdvisories[tagName] = append(fileStruct.VersionToAdvisories[tagName], advisoryId)
	}
}

func getAllSecurityAdvisories(ctx context.Context) (*packagistSecurityResponse, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://packagist.org/api/security-advisories/?packages[]=shopware/platform&packages[]=shopware/shopware", nil)

	if err != nil {
		return nil, err
	}

	r.Header.Set("User-Agent", "Shopware Security Checker")

	resp, err := http.DefaultClient.Do(r)

	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	if resp.Body.Close() != nil {
		return nil, err
	}

	var apiResponse packagistSecurityResponse

	if err = json.Unmarshal(data, &apiResponse); err != nil {
		return nil, err
	}

	return &apiResponse, nil
}

type shopwareApiResponse []struct {
    Version string `json:"version"`
}

func getSecurityPluginLatestVersion(ctx context.Context, shopwareVersion string) (string, error) {
    r, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.shopware.com/pluginStore/pluginsByName?locale=en-GB&shopwareVersion=%s&technicalNames%%5B0%%5D=SwagPlatformSecurity", shopwareVersion), nil)

    if err != nil {
        return "", err
    }

	r.Header.Set("User-Agent", "Shopware Security Checker")

	resp, err := http.DefaultClient.Do(r)

	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	if resp.Body.Close() != nil {
		return "", err
	}

	var apiResponse shopwareApiResponse

	if err = json.Unmarshal(data, &apiResponse); err != nil {
		return "", err
	}

	if len(apiResponse) == 0 {
		return "", fmt.Errorf("no plugin found")
	}

	return apiResponse[0].Version, nil
}

func findLatestVersion(tags []*github.RepositoryTag, prefix string) (string, error) {
	var latestVer *version.Version
	var latestTagName string

	for _, tag := range tags {
		name := tag.GetName()
		if !strings.HasPrefix(name, "v"+prefix) {
			continue
		}

		v, err := version.NewVersion(name)
		if err != nil {
			continue
		}

		if latestVer == nil || v.GreaterThan(latestVer) {
			latestVer = v
			latestTagName = name
		}
	}

	if latestVer == nil {
		return "", fmt.Errorf("cannot find latest version for prefix %s", prefix)
	}

	return strings.TrimPrefix(latestTagName, "v"), nil
}
