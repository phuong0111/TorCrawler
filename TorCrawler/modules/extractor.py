#!/usr/bin/python
import io
import os
import urllib.error
import urllib.parse
import urllib.request
from urllib.error import HTTPError
from urllib.error import URLError
from http.client import InvalidURL
from http.client import IncompleteRead

from bs4 import BeautifulSoup


def text(response=None):
    """Removes all the garbage from the HTML and takes only text elements
    from the page.

    :param response: HTTP Response.
    :return: String: Text only stripped response.
    """
    soup = BeautifulSoup(response, features="lxml")
    for s in soup(["script", "style"]):
        s.decompose()

    return " ".join(soup.stripped_strings)


def check_yara(raw=None, yara=0):
    """Validates Yara Rule to categorize the site and check for keywords.

    :param raw: HTTP Response body.
    :param yara:  Integer: Keyword search argument.
    :return matches: List of yara rule matches.
    """

    try:
        import yara as _yara
    except OSError:
        print(
            "YARA module error: "
            + "Try this solution: https://stackoverflow.com/a/51504326"
        )

    file_path = os.path.join("res/keywords.yar")

    if raw is not None:
        if yara == 1:
            raw = text(response=raw).lower()

        file = os.path.join(file_path)
        rules = _yara.compile(file)

        def my_call_back(data):
            return _yara.CALLBACK_CONTINUE
        matches = rules.match(
            data=raw, callback=my_call_back, which_callbacks=_yara.CALLBACK_MATCHES
        )
        if len(matches) != 0:
            print("YARA: Found a match!")
            
        import re
        for match in matches:
            matched_string = match.strings[0][2]  # Get the matched string
            for _ in match.strings:
                offset = _[0]

                # Find the span using 're'
                pattern = re.compile(re.escape(matched_string))  # Escape special characters
                re_match = pattern.match(raw, pos=offset)

                if re_match:
                    start = re_match.start()
                    end = re_match.end()
                    print(f"Matched String: {matched_string}")
                    print(f"Start Index: {start}")
                    print(f"End Index: {end}")

        return [{"tags": match.tags, "metadata": match.meta, "rule": match.rule, "strings": match.strings} for match in matches]


def cinex(input_file, out_path, yara=None):
    """Ingests the crawled links from the input_file,
    scrapes the contents of the resulting web pages and writes the contents to
    the into out_path/{url_address}.

    :param input_file: String: Filename of the crawled Urls.
    :param out_path: String: Pathname of results.
    :param yara: Integer: Keyword search argument.
    :return: None
    """
    file = io.TextIOWrapper
    try:
        file = open(input_file, "r").read()
    except IOError as err:
        print(f"Error: {err}\n## Can't open: {input_file}")

    for line in file.splitlines():

        # Generate the name for every file.
        try:
            page_name = line.rsplit("/", 1)
            cl_page_name = str(page_name[1])
            cl_page_name = cl_page_name[:-1]
            if len(cl_page_name) == 0:
                output_file = "index.htm"
            else:
                output_file = cl_page_name
        except IndexError as error:
            print(f"Error: {error}")
            continue

        # Extract page to file.
        try:
            content = urllib.request.urlopen(line, timeout=10).read()

            if yara is not None:
                full_match_keywords = check_yara(content, yara)

                if len(full_match_keywords) == 0:
                    print("No matches found.")
                    continue
                else:
                    with open(out_path + "/" + "Match.json", "w") as results:
                        results.write(str(full_match_keywords))

            with open(out_path + "/" + output_file, "wb") as results:
                results.write(content)
            print(f"# File created on: {os.getcwd()}/{out_path}/{output_file}")
        except HTTPError as e:
            print(f"Cinex Error: {e.code}, cannot access: {e.url}")
            continue
        except InvalidURL as e:
            print(f"Invalid URL: {line} \n Skipping...")
            continue
        except IncompleteRead as e:
            print(f"IncompleteRead on {line}")
            continue
        except IOError as err:
            print(f"Error: {err}\nCan't write on file: {output_file}")
    file.close()


def intermex(input_file, yara):
    """Input links from file and extract them into terminal.

    :param input_file: String: File name of links file.
    :param yara: Integer: Keyword search argument.
    :return: None
    """
    i = 0
    dir_path = os.path.split(input_file)[0]
        
    with open(input_file, "r") as file:
        for line in file:
            try:
                content = urllib.request.urlopen(line).read()
                if yara is not None:
                    full_match_keywords = check_yara(raw=content, yara=yara)
                    if len(full_match_keywords) == 0:
                        print(f"No matches in: {line}")
                # print(content)
                print(i := i + 1, line)
                output_file = line.strip('http://').rstrip() + 'home.html'
                if os.path.exists(os.path.split(output_file)[0]) == False:
                    os.makedirs(os.path.split(output_file)[0])
                with open(output_file, "wb") as file:
                    file.write(content)
            except (HTTPError, URLError, InvalidURL) as err:
                print(f"Request Error: {err}")
                continue
            except IOError as err:
                print(f"Error: {err}\n## Not valid file")
                continue


def outex(website, output_file, out_path, yara):
    """Scrapes the contents of the provided web address and outputs the
    contents to file.

    :param website: String: Url of web address to scrape.
    :param output_file: String: Filename of the results.
    :param out_path: String: Folder name of the output findings.
    :param yara: Integer: Keyword search argument.
    :return: None
    """
    # Extract page to file
    try:
        output_file = out_path + "/" + output_file
        content = urllib.request.urlopen(website).read()

        if yara is not None:
            full_match_keywords = check_yara(raw=content, yara=yara)

            if len(full_match_keywords) == 0:
                print(f"No matches in: {website}")
            else:
                with open(out_path + "/" + "Match.json", "w") as results:
                    print(out_path + "/" + "Match")
                    results.write(str(full_match_keywords))

        with open(output_file, "wb") as file:
            file.write(content)
        print(f"## File created on: {os.getcwd()}/{output_file}")
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"HTTPError: {err}")
    except IOError as err:
        print(f"Error: {err}\n Can't write on file: {output_file}")


def termex(website, yara):
    """Scrapes provided web address and prints the results to the terminal.

    :param website: String: URL of website to scrape.
    :param yara: Integer: Keyword search argument.
    :return: None
    """
    try:
        content = urllib.request.urlopen(website).read()
        if yara is not None:
            full_match_keywords = check_yara(content, yara)

            if len(full_match_keywords) == 0:
                # No match.
                print(f"No matches in: {website}")
                return

        print(content)
    except (HTTPError, URLError, InvalidURL) as err:
        print(f"Error: ({err}) {website}")
        return


def extractor(website, crawl, output_file, input_file, out_path, selection_yara):
    """Extractor - scrapes the resulting website or discovered links.

    :param website: String: URL of website to scrape.
    :param crawl: Boolean: Cinex trigger.
        If used iteratively scrape the urls from input_file.
    :param output_file: String: Filename of resulting output from scrape.
    :param input_file: String: Filename of crawled/discovered URLs
    :param out_path: String: Dir path for output files.
    :param selection_yara: String: Selected option of HTML or Text.
    :return: None
    """
    # TODO: Return output to torcrawl.py
    if len(input_file) > 0:
        if crawl:
            cinex(input_file, out_path, selection_yara)
        # TODO: Extract from list into a folder
        # elif len(output_file) > 0:
        # 	inoutex(website, input_ile, output_file)
        else:
            intermex(input_file, selection_yara)
    else:
        if len(output_file) > 0:
            outex(website, output_file, out_path, selection_yara)
        else:
            termex(website, selection_yara)
