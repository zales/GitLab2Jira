# GitLab to Jira Migrator

The GitLab to Jira Migrator is a Python tool that migrates GitLab issues (both open and closed) to Jira. It handles issue descriptions, comments, attachments, linked issues, and sub-tasks. It also supports converting Markdown (including emoji shortcodes) into Jira Wiki markup and provides persistent mapping to resume interrupted migrations.

## Features

- **Full Issue Migration:** Migrates both open and closed GitLab issues.
- **Comments & Attachments:** Migrates comments and attachments. Attachments exceeding Jira's size limit (20 MB) are skipped and replaced with fallback links.
- **Markdown Conversion:** Converts GitLab Markdown to Jira Wiki markup using the [Mistune](https://github.com/miyuchina/mistletoe) library with a custom renderer.
- **Emoji Support:** Converts GitLab emoji shortcodes to Unicode emoji.
- **Linked Issues & Sub-tasks:** Migrates linked issues and sub-tasks by using GitLab’s links API.
- **Persistent Mapping:** Uses a JSON file to store issue mappings so that an interrupted migration can resume without duplicating work.
- **Jira Epic Assignment:** Optionally assigns parent issues to a specified Jira Epic.
- **Issue Type Mapping:** Creates issues in Jira as "Bug" if the GitLab issue’s `issue_type` is `"incident"` (for parent issues); otherwise, they are created as "Task".
- **Text Truncation:** Automatically truncates long descriptions and comments to meet Jira’s 32,767-character limit and appends a Jira wiki link to the original GitLab issue (or comment).

## Requirements

- Python 3.x
- Dependencies (install via pip):
  - [python-gitlab](https://pypi.org/project/python-gitlab/)
  - [jira](https://pypi.org/project/jira/)
  - [emoji](https://pypi.org/project/emoji/)
  - [mistletoe](https://pypi.org/project/mistletoe/)

You can install the required packages with:

```bash
pip install python-gitlab jira emoji mistletoe
```

## Installation

Clone the repository and set up a virtual environment (optional but recommended):

```bash
git clone https://github.com/yourusername/gitlab-to-jira-migrator.git
cd gitlab-to-jira-migrator
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

## Usage

Run the script from the command line. For example:

```bash
python gitlab2jira.py \
    --gitlab-url https://gitlab.example.com \
    --gitlab-token YOUR_GITLAB_TOKEN \
    --gitlab-project-id 334 \
    --jira-url https://jira.example.com \
    --jira-user your.email@example.com \
    --jira-api-token YOUR_JIRA_API_TOKEN \
    --jira-project-key PROJ \
    --jira-epic-key EPIC-123 \
    --mapping-file issue_mapping.json
```

### Command-Line Arguments
	•	--gitlab-url: URL of your GitLab instance.
	•	--gitlab-token: Your GitLab access token.
	•	--gitlab-project-id: ID of the GitLab project to migrate (or use --gitlab-group-id for group migration).
	•	--gitlab-group-id: ID of the GitLab group to migrate.
	•	--jira-url: URL of your Jira instance.
	•	--jira-user: Your Jira username or email.
	•	--jira-api-token: Your Jira API token.
	•	--jira-project-key: Jira project key where the issues will be created.
	•	--jira-epic-key: (Optional) Jira Epic key to assign parent issues.
	•	--mapping-file: (Optional) JSON file to store migration mapping (default: issue_mapping.json).

### How It Works
	1.	Fetching Issues: The script retrieves issues from GitLab (for a single project or an entire group).
	2.	Markdown & Emoji Conversion: It converts issue descriptions and comments from Markdown to Jira Wiki markup while converting emoji shortcodes to Unicode.
	3.	Attachments: Attachments are downloaded from GitLab and uploaded to Jira. If an attachment exceeds 20 MB, it is skipped and replaced with a fallback link.
	4.	Comments Truncation: Comments that exceed 32,767 characters are truncated, and a Jira wiki link is appended that points directly to the original GitLab comment (if available) or issue.
	5.	Issue Type & Status: Issues are created as “Bug” if their issue_type is "incident" (for parent issues) or as “Task” otherwise. Status is determined based on GitLab labels.
	6.	Persistent Mapping: A JSON file stores the mapping between GitLab and Jira issues so that if the migration is interrupted, you can resume without duplicating work.
	7.	Jira Epic Assignment: Migrated parent issues can be automatically assigned to a specified Jira Epic.

## Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or submit a pull request on GitHub.
