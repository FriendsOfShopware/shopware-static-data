package main

import (
	"context"
	"encoding/json"
	"github.com/FriendsOfShopware/shopware-cli/version"
	"github.com/barkimedes/go-deepcopy"
	"github.com/google/go-github/v53/github"
	"io"
	"net/http"
	"os"
)

var phpVersions = []string{
	"7.0",
	"7.1",
	"7.2",
	"7.3",
	"7.4",
	"8.0",
	"8.1",
	"8.2",
	"8.3",
}

func generateAllSupportedPHPVersions(ctx context.Context, tags []*github.RepositoryTag) error {
	packagistResponse, err := fetchPackageInformation(ctx)

	if err != nil {
		return err
	}

	phpVersionMap := make(map[string][]string)

	packageVersions := expandPackagistResponse(packagistResponse.Packages["shopware/platform"])

	for _, packageVersion := range packageVersions {
		phpVersion := packageVersion["require"].(map[string]interface{})["php"].(string)
		shopwareVersion := packageVersion["version_normalized"].(string)

		phpVersionMap[shopwareVersion] = make([]string, 0)

		packageVersionConstraint := version.MustConstraints(version.NewConstraint(phpVersion))

		for _, phpVersion := range phpVersions {
			phpV := version.Must(version.NewVersion(phpVersion))

			if packageVersionConstraint.Check(phpV) {
				phpVersionMap[shopwareVersion] = append(phpVersionMap[shopwareVersion], phpVersion)
			}
		}
	}

	data, err := json.MarshalIndent(phpVersionMap, "", "  ")

	if err != nil {
		return err
	}

	if err = os.WriteFile("data/all-supported-php-versions-by-shopware-version.json", data, os.ModePerm); err != nil {
		return err
	}

	return nil
}

func expandPackagistResponse(versions []map[string]interface{}) []map[string]interface{} {
	expanded := make([]map[string]interface{}, 0)

	for index, version := range versions {
		expandedVersion := make(map[string]interface{})

		if len(expanded) > 0 {
			expandedVersion = deepcopy.MustAnything(expanded[index-1]).(map[string]interface{})
		}

		for key, value := range version {
			assertedString, _ := value.(string)

			if assertedString == "__unset" {
				delete(expandedVersion, key)
			} else {
				expandedVersion[key] = value
			}
		}

		expanded = append(expanded, expandedVersion)
	}

	return expanded
}

type packagistPackageResponse struct {
	Packages map[string][]map[string]interface{} `json:"packages"`
}

func fetchPackageInformation(ctx context.Context) (*packagistPackageResponse, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://repo.packagist.org/p2/shopware/platform.json", nil)

	if err != nil {
		return nil, err
	}

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

	var apiResponse packagistPackageResponse

	if err = json.Unmarshal(data, &apiResponse); err != nil {
		return nil, err
	}

	return &apiResponse, nil
}
