package main

import (
	"context"
	"os"

	"github.com/google/go-github/v80/github"
	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()
	var client *github.Client

	if token := os.Getenv("GITHUB_API_KEY"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	tags, err := getRepositoryTags(ctx, client)

	if err != nil {
		panic(err)
	}

	if err := generateSecurityAdvisories(ctx, tags); err != nil {
		panic(err)
	}
	if err := generateAllSupportedPHPVersions(ctx); err != nil {
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
