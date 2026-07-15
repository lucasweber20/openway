import argparse
import requests
import concurrent.futures
from furl import furl
from urllib.parse import unquote
import time


parser = argparse.ArgumentParser()

args = parser.add_argument("-u", "--url", help='Set url, example: -u https://example.com/?param=value', type=str)
args = parser.add_argument("-l", "--list", help="Specify file with urls, example: -l urls.txt", type=str)
args = parser.add_argument("-o", "--output", help="Specify output file, example: -o outputs.txt")
args = parser.add_argument("-t", "--thread", help="Specify threads number, example: -t 2", type=int)

args = parser.parse_args()

def main():
    if args.thread and args.thread > 1:
        threads = args.thread
    else:
        threads = 1

    without_duplicates = remove_duplicates(args.list)
    urls_params = check_params(without_duplicates)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(parser_urls, url) for url in urls_params]
        for future in concurrent.futures.as_completed(futures):
            urls_parsed = future.result()

    check_vuln(urls_parsed)
    
def remove_duplicates(file):
    file_read = open(file, encoding="utf-8").read().splitlines()
    result = list(dict.fromkeys(file_read))
    return result

def check_params(urls):
    params = ["?next=", "?url=", "?target=", "?rurl=", "?dest=", "?destination=", "?redir=", "?redirect_uri=", "?redirect_url=", "?redirect=", "/redirect/", "/cgi-bin/redirect.cgi?", 
              "/out/",  "/out?", "?view=", "/login?to=", "?image_url=", "?go=", "?return=", "?returnTo=", "?return_to=", "?checkout_url=", "?continue=", "?return_path=", "success=",
              "data=", "qurl=", "login=", "logout=", "ext=", "clickurl=", "goto=", "rit_url=", "forward_url=", "forward=", "pic=", "callback_url=", "jump=", "jump_url=", "click?u=",
              "originUrl=", "origin=", "Url=", "desturl=", "u=", "page=", "u1=", "action=", "action_url=", "Redirect=", "sp_url=", "service=", "recurl=", "j?url=", "url=//", "uri=",
              "u=", "allinurl:", "q=", "link=", "src=", "tc?src=", "linkAddress=", "location=", "burl=", "request=", "backurl=", "RedirectUrl=", "Redirect=", "ReturnUrl="]
    
    result = [url for param in params for url in urls if param in url]
    return result

def parser_urls(urls):
    result = []
    file_read = open("payloads.txt", encoding="utf-8").read().splitlines()
    try:
        f = furl(urls)
        for payload in file_read:
            payload = payload.replace("{domain}", f.netloc)
            for args in f.args:
                f.args[args] = payload
            else:
                result.append(unquote(f.url))
    except:
        pass
    return result

def requests_urls(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"}
    try:
        req = requests.get(url, headers=headers, timeout=10)
        if req.history:
            return True, url, req.url
    except:
        pass

def check_vuln(url_list):
    if args.thread and args.thread > 1:
        threads = args.thread
    else:
        threads = 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(requests_urls, url) for url in url_list]
        for future in concurrent.futures.as_completed(futures):
            redirect = future.result()
            if redirect:
                if args.output:
                    try:
                        file_write = open(args.output, "a").write(f"{redirect[1]} -> \033[92m{redirect[2]}\033[00m\n")
                    except:
                        continue
                print(f"Open redirect founded: {redirect[1]} -> \033[92m{redirect[2]}\033[00m")
            else:
                continue

if __name__ == "__main__":
    main()