from Bulletin import Bulletin
from generators.gh_issue import generate_gh_issue
from generators.html import generate_html
from generators.gfm import generate_gfm
from scanners import http_observatory
from scanners import security_headers
from scanners.ssllabs import ssllabs
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Checks website security using multiple scanners")
    parser.add_argument("url", type=str, help="url to scan")
    parser.add_argument("--disable-http-observatory", action="store_true", help="Disables HTTP Observatory scan")
    parser.add_argument("--disable-securityheaders", action="store_true", help="Disables SecurityHeaders scan")
    parser.add_argument("--disable-ssllabs", action="store_true", help="Disables SSLLabs scan")
    parser.add_argument("--generate-html", action="store_true", help="Generates HTML report")
    parser.add_argument("--generate-gfm", action="store_true", help="Generates GFM report")
    parser.add_argument("-o", "--output", help="Output file")

    parser.add_argument("--generate-github-issue", action="store_true", help="Generates or updates an Github Issue")
    parser.add_argument("--github-user", help="Github username")
    parser.add_argument("--github-token", help="Github token")
    parser.add_argument("--github-repo-owner", help="Github repository owner")
    parser.add_argument("--github-repo-name", help="Github repository name")


    args = parser.parse_args()


    url = str(args.url)
    url = url.replace("https://", "")
    url = url.replace("http://", "")

    bulletins: list[Bulletin] = list()

    http_obv = None
    if not args.disable_http_observatory:
        http_obv = http_observatory.HTTPObservatory(url)

    if not args.disable_securityheaders:
        bulletins.extend(security_headers.SecurityHeaders(url).GetBulletin())

    if not args.disable_ssllabs:
        bulletins.extend(ssllabs.SSLLabs(url).GetBulletin())

    if not args.disable_http_observatory:
        bulletins.extend(http_obv.GetBulletin())

    bulletins = list(set(bulletins))

    bulletins = sorted(bulletins, reverse=True)

    if args.generate_html:
        generate_html(bulletins, args.output)

    if args.generate_gfm:
        generate_gfm(bulletins, args.output)

    if args.generate_github_issue:
        generate_gh_issue(bulletins, args.github_user, args.github_token, args.github_repo_owner, args.github_repo_name)

