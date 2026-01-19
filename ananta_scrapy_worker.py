import re
import sys
import json
from typing import Dict, Any, List

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.utils.log import configure_logging

#    Appelle le worker Scrapy dans un sous-processus et renvoie un dict.
#    Le worker est ananta_scrapy_worker.py (CLI JSON).





EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"""
    (?:(?:\+|00)\d{1,3}[\s.-]?)?   # indicatif pays
    (?:\(?\d{1,4}\)?[\s.-]?)?      # indicatif régional
    (?:\d[\s.-]?){6,10}            # numéro
""", re.VERBOSE)

SOCIAL_REGEX = re.compile(
    r"(https?://(?:www\.)?(?:twitter\.com|x\.com|facebook\.com|"
    r"linkedin\.com|instagram\.com|t\.me|github\.com|gitlab\.com)"
    r"/[^\s\"'>]+)",
    re.IGNORECASE,
)


class OsintSpider(scrapy.Spider):
    name = "osint_single"

    custom_settings = {
        "USER_AGENT": "AnantaOSINTBot/1.0 (+https://example.com)",
        "ROBOTSTXT_OBEY": False,
        "DOWNLOAD_TIMEOUT": 15,
        "LOG_ENABLED": False,
    }

    def __init__(self, start_url: str, results_container: List[Dict[str, Any]], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.results_container = results_container

    def parse(self, response: scrapy.http.Response):
        # Récupération du texte principal (simpliste pour l’instant)
        text_parts = response.css("body *::text").getall()
        full_text = " ".join(t.strip() for t in text_parts if t.strip())

        title = response.css("title::text").get() or response.url

        emails = list(set(EMAIL_REGEX.findall(full_text)))
        phones = list(set(PHONE_REGEX.findall(full_text)))
        social_links = list(set(SOCIAL_REGEX.findall(full_text)))

        self.results_container.append(
            {
                "url": response.url,
                "title": title,
                "text": full_text,
                "emails": emails,
                "phone_numbers": phones,
                "social_links": social_links,
            }
        )


def run_spider(url: str) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    configure_logging()
    process = CrawlerProcess()
    process.crawl(OsintSpider, start_url=url, results_container=results)
    process.start()  # bloque jusqu'à la fin

    if not results:
        return {
            "url": url,
            "title": url,
            "text": "",
            "emails": [],
            "phone_numbers": [],
            "social_links": [],
        }

    return results[0]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "No URL provided",
            "url": None,
            "title": "",
            "text": "",
            "emails": [],
            "phone_numbers": [],
            "social_links": [],
        }, ensure_ascii=False))
        sys.exit(1)

    url = sys.argv[1]
    try:
        data = run_spider(url)
        print(json.dumps(data, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "url": url,
            "title": "",
            "text": "",
            "emails": [],
            "phone_numbers": [],
            "social_links": [],
        }, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
