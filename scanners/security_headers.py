import requests
try:
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup

from Bulletin import Bulletin, IssueLevel


class SecurityHeaders:
    url: str = None
    test_url: str = None
    soup: BeautifulSoup = None

    def __init__(self, url: str):
        print("Initializing security-headers")
        self.url = url
        self.test_url = f"https://securityheaders.com/?q={self.url}&hide=on&followRedirects=on"

        self.soup = BeautifulSoup(requests.get(self.test_url).text, "lxml")

    def GetBulletin(self) -> list[Bulletin]:
        score = self.soup.find("div", {"class": "score"}).findChildren("span", recursive=True)[0].text

        if score == "A+":
            return list()

        reports = self.soup.find_all("div", {"class": "reportSection"})

        iss = list()
        for report in reports:
            title = report.find("div", {"class": "reportTitle"}).text
            reps = ["Warnings", "Additional Information", "Missing Headers", "Upcoming Headers"]
            if title in reps:
                issues = report.findAll("tr")
                for issue in issues:
                    header = issue.find("th")
                    if "table_green" in header["class"]:
                        continue
                    description = issue.find("td").text

                    level = IssueLevel.ERR
                    if "table_orange" in header["class"]:
                        level = IssueLevel.WARN
                    elif "table_blue" in header["class"]:
                        level = IssueLevel.INFO

                    iss.append(Bulletin(header.text, description, None, level))

        return iss
