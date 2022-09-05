interface Security {
    latestPluginVersion: string;
    advisories: Record<string, Advisory>;
    versionToAdvisories: Record<string, string[]>;
}

interface Advisory {
    title: string;
    link: string;
    cve: string;
    affectedVersions: string;
    source: string;
    reportedAt: string;
}
