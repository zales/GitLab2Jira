#!/usr/bin/env python
"""
GitLab2Jira Migrator
--------------------

This open source tool migrates issues from GitLab to Jira. It transfers both open and closed issues,
including comments, attachments, linked issues, and sub-tasks. The tool converts GitLab Markdown
to Jira Wiki markup, translates emoji shortcodes into Unicode, maps GitLab incidents to Jira Bugs,
and supports resuming interrupted migrations via persistent mapping.

Usage:
    python gitlab2jira.py \
      --gitlab-url https://gitlab.example.com \
      --gitlab-token YOUR_GITLAB_TOKEN \
      [--gitlab-project-id 334 | --gitlab-group-id YOUR_GROUP_ID] \
      --jira-url https://jira.example.com \
      --jira-user your.email@example.com \
      --jira-api-token YOUR_JIRA_API_TOKEN \
      --jira-project-key PROJ \
      [--jira-epic-key EPIC-123] \
      [--mapping-file issue_mapping.json]
"""

import html
import json
import logging
import gitlab
from jira import JIRA
from jira.exceptions import JIRAError
import argparse
import os
import re
import urllib.parse
import emoji
import mistletoe
from mistletoe import block_token, span_token
from mistletoe.base_renderer import BaseRenderer

# ----------------------------
# Logging configuration
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


# ----------------------------
# Mapping persistence functions
# ----------------------------
def load_mapping(mapping_file):
    """
    Load the migration mapping from a JSON file.

    :param mapping_file: Path to the mapping file.
    :return: A dictionary containing the mapping.
    """
    if os.path.exists(mapping_file):
        try:
            with open(mapping_file, "r", encoding="utf-8") as f:
                mapping = json.load(f)
            logger.info(f"Loaded mapping from {mapping_file}")
            return mapping
        except Exception as e:
            logger.error(f"Error loading mapping from {mapping_file}: {e}", exc_info=True)
    return {}


def save_mapping(mapping_file, mapping):
    """
    Save the migration mapping to a JSON file.

    :param mapping_file: Path to the mapping file.
    :param mapping: The mapping dictionary to save.
    """
    try:
        with open(mapping_file, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2)
        logger.info(f"Saved mapping to {mapping_file}")
    except Exception as e:
        logger.error(f"Error saving mapping to {mapping_file}: {e}", exc_info=True)


# ----------------------------
# JIRA Renderer
# ----------------------------
def escape_url(raw: str) -> str:
    """
    URL-encodes a raw string, preserving certain safe characters.

    :param raw: The raw URL string.
    :return: URL-encoded string.
    """
    from urllib.parse import quote
    return quote(raw, safe='/#:')


class JIRARenderer(BaseRenderer):
    """
    Custom renderer that converts Markdown tokens into Jira Wiki markup.
    """
    def __init__(self, *extras):
        """
        Initialize the JIRARenderer.
        """
        self.list_tokens = []
        super().__init__(block_token.HTMLBlock, span_token.HTMLSpan, *extras)

    def render_strong(self, token):
        """Render bold text."""
        return f"*{self.render_inner(token)}*"

    def render_emphasis(self, token):
        """Render italic text."""
        return f"_{self.render_inner(token)}_"

    def render_inline_code(self, token):
        """Render inline code."""
        return f"{{{{{self.render_inner(token)}}}}}"

    def render_strikethrough(self, token):
        """Render strikethrough text."""
        return f"-{self.render_inner(token)}-"

    def render_image(self, token):
        """Render an image."""
        return f"!{token.src}!"

    def render_link(self, token):
        """
        Render a hyperlink.
        Replaces square brackets in the link text with parentheses to avoid Jira conflicts.
        """
        inner = self.render_inner(token)
        # Replace any square brackets inside the link text with parentheses.
        sanitized_inner = inner.replace("[", "(").replace("]", ")")
        return f"[{sanitized_inner}|{token.target}]"

    def render_auto_link(self, token):
        """Render an auto link."""
        return f"[{token.target}]"

    def render_escape_sequence(self, token):
        """Render escape sequence."""
        return self.render_inner(token)

    @staticmethod
    def render_raw_text(token):
        """Render raw text."""
        import html
        return html.escape(token.content)

    @staticmethod
    def render_html_span(token):
        """Render an HTML span."""
        return token.content

    def render_heading(self, token):
        """Render a heading."""
        return f"h{token.level}. {self.render_inner(token)}\n\n"

    def render_quote(self, token):
        """Render a blockquote."""
        return f"bq. {self.render_inner(token)}\n"

    def render_paragraph(self, token):
        """Render a paragraph."""
        return f"{self.render_inner(token)}\n"

    def render_block_code(self, token):
        """Render a block of code."""
        attr = token.language or ""
        inner = self.render_inner(token)
        return f"{{code:{attr}}}\n{inner}{{code}}\n"

    def render_list(self, token):
        """Render a list."""
        return self.render_inner(token) + "\n"

    def render_list_item(self, token):
        """Render a list item."""
        prefix = "".join(self.list_tokens)
        inner = self.render_inner(token)
        if not inner.endswith('\n'):
            inner += '\n'
        return f"{prefix} {inner}"

    def render_inner(self, token):
        """
        Recursively render inner tokens.
        """
        if isinstance(token, block_token.List):
            if token.start is not None:
                self.list_tokens.append('#')
            else:
                self.list_tokens.append('*')
        rendered = [self.render(child) for child in token.children]
        if isinstance(token, block_token.List):
            self.list_tokens.pop()
        return "".join(rendered)

    def render_table(self, token):
        """Render a table."""
        head_rendered = ""
        if hasattr(token, 'header') and token.header is not None:
            head_rendered = self.render_table_row(token.header, is_header=True)
        body_rendered = self.render_inner(token)
        return f"{head_rendered}{body_rendered}\n"

    def render_table_row(self, token, is_header=False):
        """Render a table row."""
        if is_header:
            row_inner = "".join([self.render_table_cell(child, True) for child in token.children])
            return f"{row_inner}||\n"
        else:
            row_inner = "".join([self.render_table_cell(child, False) for child in token.children])
            return f"{row_inner}|\n"

    def render_table_cell(self, token, in_header=False):
        """Render a table cell."""
        inner = self.render_inner(token) or " "
        return f"{'||' if in_header else '|'}{inner}"

    @staticmethod
    def render_thematic_break(token):
        """Render a thematic break."""
        return "----\n"

    @staticmethod
    def render_line_break(token):
        """Render a line break."""
        return " "

    @staticmethod
    def render_html_block(token):
        """Render an HTML block."""
        return token.content

    def render_document(self, token):
        """Render the full document."""
        self.footnotes.update(token.footnotes)
        return self.render_inner(token)


# ----------------------------
# Markdown conversion functions
# ----------------------------
def markdown_to_jira(text: str) -> str:
    """
    Convert a Markdown string into Jira Wiki markup using the JIRARenderer.

    :param text: Markdown text.
    :return: Converted Jira Wiki markup.
    """
    if not text:
        return ""
    return mistletoe.markdown(text, JIRARenderer)


def convert_markdown_checkboxes_to_json(markdown_text):
    """
    Convert Markdown checkboxes to Jira JSON format for task lists.

    :param markdown_text: Markdown text containing checkboxes.
    :return: JSON object representing the task list.
    """
    import uuid
    lines = markdown_text.split("\n")
    task_list = {"type": "taskList", "content": []}
    for line in lines:
        match = re.match(r"- \[(x| )\] (.+)", line.strip(), re.IGNORECASE)
        if match:
            state = "DONE" if match.group(1).lower() == "x" else "TODO"
            text = match.group(2)
            task_item = {
                "type": "taskItem",
                "content": [{"type": "text", "text": text}],
                "attrs": {"localId": str(uuid.uuid4()), "state": state},
            }
            task_list["content"].append(task_item)
    return task_list


# ----------------------------
# GitLab to Jira Migrator class
# ----------------------------
class GitLabToJiraMigrator:
    """
    Migrates GitLab issues to Jira.

    This class handles fetching issues from GitLab, converting their content (Markdown, attachments, etc.)
    to the format expected by Jira, and creating/updating issues in Jira. It supports resuming an interrupted
    migration using a persistent mapping file.
    """
    def __init__(self,
                 gitlab_url,
                 gitlab_token,
                 jira_url,
                 jira_user,
                 jira_api_token,
                 jira_project_key,
                 jira_epic_key=None,
                 gitlab_project_id=None,
                 gitlab_group_id=None,
                 mapping_file="issue_mapping.json"):
        """
        Initialize the migrator.

        :param gitlab_url: URL of the GitLab instance.
        :param gitlab_token: GitLab access token.
        :param jira_url: URL of the Jira instance.
        :param jira_user: Jira username or email.
        :param jira_api_token: Jira API token.
        :param jira_project_key: Jira project key to create issues in.
        :param jira_epic_key: (Optional) Jira Epic key to assign parent issues.
        :param gitlab_project_id: GitLab project ID.
        :param gitlab_group_id: GitLab group ID.
        :param mapping_file: File path to store issue mapping.
        """
        logger.info("Connecting to GitLab...")
        self.gitlab = gitlab.Gitlab(gitlab_url, private_token=gitlab_token)
        self.gitlab_url = gitlab_url.rstrip('/')
        if gitlab_group_id:
            logger.info(f"Fetching GitLab group {gitlab_group_id} ...")
            group = self.gitlab.groups.get(gitlab_group_id)
            self.projects = group.projects.list(include_subgroups=True, all=True)
            logger.info(f"Found {len(self.projects)} projects in group {gitlab_group_id}.")
        elif gitlab_project_id:
            project = self.gitlab.projects.get(gitlab_project_id)
            self.projects = [project]
            logger.info(f"Using GitLab project {gitlab_project_id}.")
        else:
            raise ValueError("Either --gitlab-project-id or --gitlab-group-id must be provided.")
        logger.info("Connecting to Jira...")
        jira_options = {"server": jira_url}
        self.jira = JIRA(jira_options, basic_auth=(jira_user, jira_api_token))
        self.jira_project_key = jira_project_key
        self.jira_epic_key = jira_epic_key
        self.mapping_file = mapping_file
        self.issue_mapping = load_mapping(mapping_file)

    def get_jira_account_id_by_email(self, email):
        """
        Retrieve the Jira accountId using the user's email.

        :param email: Email address.
        :return: Jira accountId or None.
        """
        try:
            users = self.jira.search_users(query=email, maxResults=1)
            if users:
                return users[0].accountId
            else:
                logger.warning(f"No Jira account found for email {email}")
                return None
        except Exception as e:
            logger.error(f"Error searching Jira user by email {email}: {e}", exc_info=True)
            return None

    # --- Attachment handling methods ---
    def _extract_filename_from_content_disposition(self, content_disp, default_name):
        """
        Extract the filename from the Content-Disposition header.

        :param content_disp: Content-Disposition header string.
        :param default_name: Default filename if extraction fails.
        :return: Extracted filename.
        """
        if not content_disp:
            return default_name
        parts = re.split(r';\s*', content_disp)
        filename = None
        for part in parts:
            if part.lower().startswith("filename*="):
                val = part.split("=", 1)[1].strip()
                val = re.sub(r"^UTF-8''", "", val, flags=re.IGNORECASE)
                val = val.strip('"')
                filename = urllib.parse.unquote(val)
                break
            elif part.lower().startswith("filename="):
                val = part.split("=", 1)[1].strip().strip('"')
                filename = val
        if not filename:
            filename = default_name
        return filename

    def _download_file_by_secret(self, secret, filename, destination_name, project):
        """
        Download an attachment from GitLab using a secret.

        :param secret: The secret token for the upload.
        :param filename: The filename to download.
        :param destination_name: The destination filename.
        :param project: GitLab project object.
        :return: Path to the downloaded file or None if failed.
        """
        endpoint = f"/projects/{project.id}/uploads/{secret}/{filename}"
        try:
            response = self.gitlab.http_get(endpoint, streamed=True)
            if response.status_code == 200:
                content_disp = response.headers.get("Content-Disposition", "")
                final_name = self._extract_filename_from_content_disposition(content_disp, destination_name)
                with open(final_name, "wb") as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        f.write(chunk)
                logger.info(f"Downloaded: {final_name}")
                return final_name
            else:
                logger.warning(f"Failed to download (secret={secret}, filename={filename}). HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error downloading file: {e}", exc_info=True)
            return None

    def _upload_file_to_jira(self, jira_issue_key, local_path):
        """
        Upload a file to a Jira issue as an attachment.

        :param jira_issue_key: Key of the Jira issue.
        :param local_path: Path to the local file.
        :return: True if successful, False otherwise.
        """
        max_allowed_size = 20971520  # 20 MB
        try:
            file_size = os.path.getsize(local_path)
            if file_size > max_allowed_size:
                logger.warning(f"Skipping upload of {local_path}: file size {file_size} exceeds max allowed size {max_allowed_size}")
                os.remove(local_path)
                return False
            self.jira.add_attachment(issue=jira_issue_key, attachment=local_path)
            logger.info(f"Uploaded to Jira: {local_path}")
            os.remove(local_path)
            return True
        except Exception as e:
            logger.error(f"Error uploading file to Jira: {e}", exc_info=True)
            return False

    def _replace_and_upload_attachments_in_md(self, jira_issue_key, md_text, project):
        """
        Find and process attachments in Markdown text:
          - Download the attachment from GitLab.
          - Attempt to upload it to Jira.
          - If successful, replace the Markdown image/file syntax with Jira's inline attachment syntax.
          - If upload fails, replace with a fallback link.

        :param jira_issue_key: Jira issue key.
        :param md_text: Markdown text containing attachment references.
        :param project: GitLab project object.
        :return: Modified Markdown text.
        """
        pattern = r'(!?)\[(.*?)\]\(/uploads/([0-9a-fA-F]{32})/([^)]+)\)'
        matches = re.findall(pattern, md_text)
        if not matches:
            logger.info("No attachments found in Markdown.")
            return md_text
        new_text = md_text
        for is_image, alt_text, secret, filename in matches:
            logger.info(f"Processing attachment: alt='{alt_text}', secret='{secret}', filename='{filename}'")
            local_path = self._download_file_by_secret(secret, filename, filename, project)
            if local_path:
                upload_success = self._upload_file_to_jira(jira_issue_key, local_path)
                if upload_success:
                    jira_attachment_reference = f"!{filename}!"
                else:
                    original_url = f"{self.gitlab_url}/-/project/{project.id}/uploads/{secret}/{filename}"
                    jira_attachment_reference = f"[{alt_text}|{original_url}]"
                snippet_regex = re.escape(f"{is_image}[{alt_text}](/uploads/{secret}/{filename})")
                new_text = re.sub(snippet_regex, jira_attachment_reference, new_text)
                logger.info(f"Replaced Markdown reference for file: {filename}")
            else:
                logger.error(f"Failed to process attachment: {filename}")
        return new_text

    # --- Parent/Linked Issues Handling ---
    def determine_parent_from_links(self, gitlab_issue, project):
        """
        Determine if the GitLab issue is a sub-task by checking the links API.
        
        :param gitlab_issue: GitLab issue object.
        :param project: GitLab project object.
        :return: The parent issue's IID if found, otherwise None.
        """
        try:
            endpoint = f"/projects/{project.id}/issues/{gitlab_issue.iid}/links"
            links = self.gitlab.http_get(endpoint)
            if links:
                for link in links:
                    if link.get("link_type", "").lower() == "is_child":
                        if link.get("target_issue_iid") == gitlab_issue.iid:
                            return link.get("source_issue_iid")
            return None
        except Exception as e:
            logger.error(f"Error fetching links for GitLab issue #{gitlab_issue.iid}: {e}", exc_info=True)
            return None

    def get_linked_issues(self, gitlab_issue, project):
        """
        Retrieve issues linked to the current GitLab issue.

        :param gitlab_issue: GitLab issue object.
        :param project: GitLab project object.
        :return: List of dictionaries with 'title' and 'web_url' for each linked issue.
        """
        try:
            endpoint = f"/projects/{project.id}/issues/{gitlab_issue.iid}/links"
            links = self.gitlab.http_get(endpoint)
            linked_issues = []
            if isinstance(links, list):
                for link in links:
                    if link.get("link_type", "").lower() != "is_child":
                        try:
                            linked_issues.append({
                                "title": link['title'],
                                "web_url": link['web_url']
                            })
                        except Exception as e:
                            logger.error(f"Error fetching linked issue #{link['title']}: {e}", exc_info=True)
            return linked_issues
        except Exception as e:
            logger.error(f"Error fetching linked issues for GitLab issue #{gitlab_issue.iid}: {e}", exc_info=True)
            return []

    def get_child_issues(self, gitlab_issue, project):
        """
        Retrieve child issues (sub-tasks) linked to the current GitLab issue.

        :param gitlab_issue: GitLab issue object.
        :param project: GitLab project object.
        :return: List of dictionaries with 'title' and 'web_url' for each child issue.
        """
        try:
            endpoint = f"/projects/{project.id}/issues/{gitlab_issue.iid}/links"
            links = self.gitlab.http_get(endpoint)
            child_issues = []
            if isinstance(links, list):
                for link in links:
                    if link.get("link_type", "").lower() == "is_child":
                        try:
                            child_issues.append({
                                "title": link['title'],
                                "web_url": link['web_url']
                            })
                        except Exception as e:
                            logger.error(f"Error fetching child issue #{link['title']}: {e}", exc_info=True)
            return child_issues
        except Exception as e:
            logger.error(f"Error fetching child issues for GitLab issue #{gitlab_issue.iid}: {e}", exc_info=True)
            return []

    # --- Status Conversion ---
    def get_desired_jira_status(self, gitlab_issue):
        """
        Determine the desired Jira status based on the GitLab issue's state and labels.

        :param gitlab_issue: GitLab issue object.
        :return: A string representing the Jira status.
        """
        mapping = {
            "To Do": "To Do",
            "Doing": "Doing",
            "QAReady": "QA Ready",
            "QA Tested": "QA Tested",
            "ReleaseReady": "Release Ready",
            "Done": "Done",
            "Closed": "Done",
        }
        if gitlab_issue.state.lower() == 'closed':
            return "Done"
        for label in gitlab_issue.labels:
            normalized_label = label.replace("_", " ").strip()
            if normalized_label in mapping:
                return mapping[normalized_label]
        return "To Do"

    def transition_issue_to_status(self, jira_issue, desired_status):
        """
        Transition a Jira issue to the desired status if a matching transition is available.

        :param jira_issue: Jira issue object.
        :param desired_status: Desired status string.
        :return: True if transition is successful, otherwise False.
        """
        try:
            transitions = self.jira.transitions(jira_issue)
            available_statuses = []
            for transition in transitions:
                to_status = transition.get('to', {}).get('name', '')
                available_statuses.append(to_status)
                if to_status.lower() == desired_status.lower():
                    self.jira.transition_issue(jira_issue, transition['id'])
                    logger.info(f"Transitioned {jira_issue.key} to {desired_status}")
                    return True
            logger.warning(
                f"Desired status '{desired_status}' not available for issue {jira_issue.key}. "
                f"Available statuses: {', '.join(available_statuses)}"
            )
        except Exception as e:
            logger.error(f"Error transitioning issue {jira_issue.key} to status {desired_status}: {e}", exc_info=True)
        return False

    # --- Issue Creation & Migration ---
    def create_jira_issue(self, gitlab_issue, project):
        """
        Create a Jira issue from a GitLab issue.

        This method prepares the description, converts Markdown,
        handles attachments, sets the issue type (maps 'incident' to 'Bug'),
        and creates the issue in Jira. If the description is too long,
        it is truncated with a link to the original GitLab issue.

        :param gitlab_issue: GitLab issue object.
        :param project: GitLab project object.
        :return: The Jira issue key if created successfully, otherwise None.
        """
        original_desc = gitlab_issue.description or ""
        parent_id = self.determine_parent_from_links(gitlab_issue, project)
        linked_issues = self.get_linked_issues(gitlab_issue, project)
        child_issues = self.get_child_issues(gitlab_issue, project)
        additional_description = []
        gitlab_link_description = f"### Original GitLab Issue:\n- [{gitlab_issue.title}]({gitlab_issue.web_url})"
        additional_description.append(gitlab_link_description)
        if linked_issues:
            linked_titles = [f"- [{issue['title']}]({issue['web_url']})" for issue in linked_issues]
            linked_description = "### Linked Issues:\n" + "\n".join(linked_titles)
            additional_description.append(linked_description)
        if child_issues:
            child_titles = [f"- [{issue['title']}]({issue['web_url']})" for issue in child_issues]
            child_description = "### Child Issues:\n" + "\n".join(child_titles)
            additional_description.append(child_description)
        final_description = original_desc
        if additional_description:
            if final_description.strip():
                final_description += "\n\n"
            final_description += "\n\n".join(additional_description)
        desc_jira = self.convert_markdown_to_jira(final_description)
        # Truncate description if it exceeds Jira's limit and append a link to the original issue
        MAX_DESCRIPTION_LENGTH = 32767
        if len(desc_jira) > MAX_DESCRIPTION_LENGTH:
            logger.warning(f"Issue description for GitLab issue #{gitlab_issue.iid} exceeds {MAX_DESCRIPTION_LENGTH} characters. Truncating.")
            truncate_notice = f"\n\n[description truncated|{gitlab_issue.web_url}]"
            allowed_length = MAX_DESCRIPTION_LENGTH - len(truncate_notice)
            desc_jira = desc_jira[:allowed_length] + truncate_notice
        labels = [label.replace(" ", "_") for label in gitlab_issue.labels]
        issue_data = {
            "project": {"key": self.jira_project_key},
            "summary": gitlab_issue.title,
            "description": desc_jira,
            "labels": labels,
        }
        # Set reporter if available
        if hasattr(gitlab_issue, "author") and gitlab_issue.author:
            try:
                user = self.gitlab.users.get(gitlab_issue.author['id'])
                gitlab_reporter_email = user.email
                logger.info(f"Reporter email: {gitlab_reporter_email}")
                jira_reporter = self.get_jira_account_id_by_email(gitlab_reporter_email)
                if jira_reporter:
                    issue_data["reporter"] = {"accountId": jira_reporter}
                else:
                    logger.warning(f"Could not find Jira accountId for reporter with email {gitlab_reporter_email}.")
            except Exception as e:
                logger.error(f"Error fetching author details (ID: {gitlab_issue.author.get('id')}): {e}", exc_info=True)
        else:
            logger.warning("GitLab issue does not contain author information.")
        # Set assignee if available
        if hasattr(gitlab_issue, "assignee") and gitlab_issue.assignee:
            try:
                user = self.gitlab.users.get(gitlab_issue.assignee['id'])
                gitlab_assignee_email = user.email
                logger.info(f"Assignee email: {gitlab_assignee_email}")
                jira_assignee = self.get_jira_account_id_by_email(gitlab_assignee_email)
                if jira_assignee:
                    issue_data["assignee"] = {"accountId": jira_assignee}
                else:
                    logger.warning(f"Could not find Jira accountId for assignee with email {gitlab_assignee_email}.")
            except Exception as e:
                logger.error(f"Error fetching assignee details (ID: {gitlab_issue.assignee.get('id')}): {e}", exc_info=True)
        else:
            logger.warning("GitLab issue does not contain assignee information.")
        # If the issue is a sub-task, set its parent; otherwise set the issue type.
        if parent_id is not None:
            parent_jira_key = self.issue_mapping.get(f"{project.id}-{parent_id}")
            if not parent_jira_key:
                logger.error(f"Parent Jira key not found for GitLab issue #{gitlab_issue.iid} (parent_id={parent_id}) in project {project.id}. Skipping sub-task creation.")
                return None
            issue_data["issuetype"] = {"name": "Sub-task"}
            issue_data["parent"] = {"key": parent_jira_key}
        else:
            if hasattr(gitlab_issue, "issue_type") and gitlab_issue.issue_type.lower() == "incident":
                issue_data["issuetype"] = {"name": "Bug"}
            else:
                issue_data["issuetype"] = {"name": "Task"}
        # Create the Jira issue
        try:
            new_issue = self.jira.create_issue(fields=issue_data)
            logger.info(f"Created Jira issue: {new_issue.key} (GitLab issue #{gitlab_issue.iid} from project {project.id})")
        except JIRAError as e:
            if "cannot be assigned" in str(e):
                logger.warning(f"Assignee cannot be assigned for GitLab issue #{gitlab_issue.iid}. Removing assignee and retrying.")
                if "assignee" in issue_data:
                    del issue_data["assignee"]
                try:
                    new_issue = self.jira.create_issue(fields=issue_data)
                    logger.info(f"Created Jira issue without assignee: {new_issue.key} (GitLab issue #{gitlab_issue.iid} from project {project.id})")
                except Exception as e:
                    logger.error(f"Error creating Jira issue for GitLab #{gitlab_issue.iid} even after removing assignee: {e}", exc_info=True)
                    return None
            else:
                logger.error(f"Error creating Jira issue for GitLab #{gitlab_issue.iid}: {e}", exc_info=True)
                return None
        # Transition the issue to the desired status if necessary
        desired_status = self.get_desired_jira_status(gitlab_issue)
        current_status = new_issue.fields.status.name
        if current_status.lower() != desired_status.lower():
            self.transition_issue_to_status(new_issue, desired_status)
        else:
            logger.info(f"Issue {new_issue.key} is already in '{desired_status}' state; no transition needed.")
        # Process attachments in the description
        replaced_md = self._replace_and_upload_attachments_in_md(new_issue.key, final_description, project)
        final_desc_jira = self.convert_markdown_to_jira(replaced_md)
        final_desc_jira = html.unescape(final_desc_jira)
        if len(final_desc_jira) > MAX_DESCRIPTION_LENGTH:
            logger.warning(f"Final description for {new_issue.key} exceeds limit. Truncating.")
            truncate_notice = f"\n\n[description truncated|{gitlab_issue.web_url}]"
            allowed_length = MAX_DESCRIPTION_LENGTH - len(truncate_notice)
            final_desc_jira = final_desc_jira[:allowed_length] + truncate_notice
        try:
            new_issue.update(fields={"description": final_desc_jira})
            logger.info(f"Updated description for {new_issue.key}")
        except Exception as e:
            logger.error(f"Error updating description for {new_issue.key}: {e}", exc_info=True)
        # Always assign to Epic if provided (only for parent issues)
        if parent_id is None and self.jira_epic_key:
            update_data = {"parent": {"key": self.jira_epic_key}}
            try:
                new_issue.update(fields=update_data)
                logger.info(f"Issue {new_issue.key} was assigned to Epic {self.jira_epic_key}.")
            except Exception as e:
                logger.error(f"Error updating issue {new_issue.key} with Epic link: {e}", exc_info=True)
        self.issue_mapping[f"{project.id}-{gitlab_issue.iid}"] = new_issue.key
        save_mapping(self.mapping_file, self.issue_mapping)
        return new_issue.key

    def migrate_comments(self, gitlab_issue, jira_issue_key, project):
        """
        Migrate comments from a GitLab issue to a corresponding Jira issue.

        If a comment exceeds the maximum length, it is truncated and a link is appended that points
        directly to the original GitLab comment.
        """
        MAX_COMMENT_LENGTH = 32767
        for note in gitlab_issue.notes.list(all=True):
            if note.system:
                logger.info(f"Skipping system note: {note.body[:50]}...")
                continue
            author = note.author["name"]
            original_body = html.unescape(note.body or "")
            replaced_md = self._replace_and_upload_attachments_in_md(jira_issue_key, original_body, project)
            replaced_jira = self.convert_markdown_to_jira(replaced_md)
            final_comment_body = f"*{author} wrote:*\n\n{replaced_jira}"
            if len(final_comment_body) > MAX_COMMENT_LENGTH:
                logger.warning(f"Comment from {author} exceeds maximum length, truncating.")
                # Use note.web_url if available; otherwise, construct using issue URL and note id.
                if hasattr(note, "web_url") and note.web_url:
                    comment_link = note.web_url
                else:
                    comment_link = f"{gitlab_issue.web_url}#note_{note.id}"
                truncate_notice = f"\n\n[comment truncated|{comment_link}]"
                allowed_length = MAX_COMMENT_LENGTH - len(truncate_notice)
                final_comment_body = final_comment_body[:allowed_length] + truncate_notice
            try:
                self.jira.add_comment(jira_issue_key, html.unescape(final_comment_body))
                logger.info(f"Comment migrated from {author}: {original_body[:50]}...")
            except Exception as e:
                logger.error(f"Error migrating comment from {author}: {e}", exc_info=True)

    def migrate_issues(self):
        """
        Migrate issues for all projects.

        Loads the persistent mapping and iterates through each GitLab issue,
        creating a corresponding Jira issue if it hasn't been migrated yet.
        """
        self.issue_mapping = load_mapping(self.mapping_file)
        for project in self.projects:
            full_project = self.gitlab.projects.get(project.id)
            logger.info(f"\n=== Processing GitLab project {full_project.id} ===")
            gitlab_issues = full_project.issues.list(state='all', all=True)
            sorted_issues = sorted(gitlab_issues, key=lambda issue: issue.iid)
            for gitlab_issue in sorted_issues:
                key = f"{project.id}-{gitlab_issue.iid}"
                if key in self.issue_mapping:
                    logger.info(f"Skipping already migrated issue #{gitlab_issue.iid}")
                    continue
                logger.info(f"\n=== Processing GitLab issue #{gitlab_issue.iid} from project {full_project.id}: {gitlab_issue.title} ===")
                jira_key = self.create_jira_issue(gitlab_issue, full_project)
                if jira_key:
                    self.migrate_comments(gitlab_issue, jira_key, full_project)

def main():
    parser = argparse.ArgumentParser(
        description="Migrate all GitLab issues (open and closed) to Jira and assign them to an Epic if specified."
    )
    parser.add_argument("--gitlab-url", required=True, help="URL of the GitLab instance")
    parser.add_argument("--gitlab-token", required=True, help="GitLab access token")
    parser.add_argument("--gitlab-project-id", help="GitLab project ID")
    parser.add_argument("--gitlab-group-id", help="GitLab group ID")
    parser.add_argument("--jira-url", required=True, help="URL of the Jira instance")
    parser.add_argument("--jira-user", required=True, help="Jira email or username")
    parser.add_argument("--jira-api-token", required=True, help="Jira API token")
    parser.add_argument("--jira-project-key", required=True, help="Jira project key")
    parser.add_argument("--jira-epic-key", help="Jira Epic key to assign parent issues (optional)", default=None)
    parser.add_argument("--mapping-file", help="File to store migration mapping", default="issue_mapping.json")

    args = parser.parse_args()

    migrator = GitLabToJiraMigrator(
        gitlab_url=args.gitlab_url,
        gitlab_token=args.gitlab_token,
        jira_url=args.jira_url,
        jira_user=args.jira_user,
        jira_api_token=args.jira_api_token,
        jira_project_key=args.jira_project_key,
        jira_epic_key=args.jira_epic_key,
        gitlab_project_id=args.gitlab_project_id,
        gitlab_group_id=args.gitlab_group_id,
        mapping_file=args.mapping_file
    )

    migrator.migrate_issues()

if __name__ == "__main__":
    main()
