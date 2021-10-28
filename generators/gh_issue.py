from typing import List

from github3 import login
from github3.issues import ShortIssue

from Bulletin import Bulletin
from generators.gfm import generate_gfm_str


def generate_gh_issue(bulletins: List[Bulletin], user: str, token: str, repo_owner: str, repo_name: str):
    print("Generating Github issue")
    gh = login(username=user, token=token)

    issues = gh.issues_on(username=repo_owner, repository=repo_name)

    issue_text = generate_gfm_str(bulletins)

    issue: ShortIssue
    for issue in issues:
        if issue.title == "[SECURITY] WebSecCheck Issues":
            issue.edit(body=issue_text)
            issue.create_comment("Updated issue list")
            return

    issue: ShortIssue = gh.create_issue(repo_owner, repo_name, "[SECURITY] WebSecCheck Issues", body=issue_text)
    print(issue.as_json())