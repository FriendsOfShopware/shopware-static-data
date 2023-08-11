package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/FriendsOfShopware/shopware-cli/version"
	"github.com/google/go-github/v53/github"
	"io"
	"net/http"
	"os"
)

type packagistSecurityResponse struct {
	Advisories struct {
		ShopwarePlatform []struct {
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
		} `json:"shopware/platform"`
	} `json:"advisories"`
}

func generateSecurityAdvisories(ctx context.Context, tags []*github.RepositoryTag) error {
	packagistAdvisories, err := getAllSecurityAdvisories(ctx)

	if err != nil {
		return err
	}

	latestVersion, err := getSecurityPluginLatestVersion(ctx)

	if err != nil {
		return err
	}

	fileStruct := securityFile{
		LatestPluginVersion: latestVersion,
		Advisories:          make(map[string]advisories),
		VersionToAdvisories: make(map[string][]string),
	}

	for _, advisory := range packagistAdvisories.Advisories.ShopwarePlatform {
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

		for _, advisory := range packagistAdvisories.Advisories.ShopwarePlatform {
			constraint := version.MustConstraints(version.NewConstraint(advisory.AffectedVersions))

			if constraint.Check(v) {
				if fileStruct.VersionToAdvisories[tag.GetName()] == nil {
					fileStruct.VersionToAdvisories[tag.GetName()] = []string{}
				}

				fileStruct.VersionToAdvisories[tag.GetName()] = append(fileStruct.VersionToAdvisories[tag.GetName()], advisory.AdvisoryId)
			}
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

func getAllSecurityAdvisories(ctx context.Context) (*packagistSecurityResponse, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://packagist.org/api/security-advisories/?packages[]=shopware/platform", nil)

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

func getSecurityPluginLatestVersion(ctx context.Context) (string, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.shopware.com/pluginStore/pluginsByName?locale=en-GB&shopwareVersion=6.4.14.0&technicalNames%5B0%5D=SwagPlatformSecurity", nil)

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
