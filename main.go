package main

import (
	"context"
	"github.com/google/go-github/v53/github"
)

func main() {
	ctx := context.Background()
	client := github.NewClient(nil)

	tags, err := getRepositoryTags(ctx, client)

	if err != nil {
		panic(err)
	}

	if err := generateSecurityAdvisories(ctx, tags); err != nil {
		panic(err)
	}
	if err := generatePHPMinMap(ctx, tags); err != nil {
		panic(err)
	}
	if err := generateAllSupportedPHPVersions(ctx, tags); err != nil {
		panic(err)
	}
}

func getRepositoryTags(ctx context.Context, client *github.Client) ([]*github.RepositoryTag, error) {
	tags := make([]*github.RepositoryTag, 0)

	opts := &github.ListOptions{
		PerPage: 100,
	}
	for {
		paginated, resp, err := client.Repositories.ListTags(ctx, "shopware", "shopware", opts)
		if err != nil {
			return nil, err
		}

		tags = append(tags, paginated...)

		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	return tags, nil
}
