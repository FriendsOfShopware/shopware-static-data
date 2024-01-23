package main

import (
	"context"
	"encoding/json"
	"github.com/google/go-github/v53/github"
	"os"
	"strings"
)

func generatePHPMinMap(ctx context.Context, tags []*github.RepositoryTag) error {
	phpMinMap := make(map[string]string)

	for _, tag := range tags {
		tagName := strings.TrimPrefix(tag.GetName(), "v")

		if strings.HasPrefix(tagName, "6.6") {
			phpMinMap[tagName] = "8.2"
		} else if strings.HasPrefix(tagName, "6.5") {
			phpMinMap[tagName] = "8.1"
		} else if strings.HasPrefix(tagName, "6.4") {
			phpMinMap[tagName] = "7.4"
		} else {
			phpMinMap[tagName] = "7.2"
		}
	}

	data, err := json.MarshalIndent(phpMinMap, "", "  ")

	if err != nil {
		return err
	}

	if err = os.WriteFile("data/php-version.json", data, os.ModePerm); err != nil {
		return err
	}

	return nil
}
