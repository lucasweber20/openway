import argparse
import requests
import concurrent.futures
from furl import furl
from urllib.parse import unquote


HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"}

parser = argparse.ArgumentParser()

args = parser.add_argument("-u", "--url", help='Set url, example: -u https://example.com/?param=value', type=str)
args = parser.add_argument("-l", "--list", help="Specify file with urls, example: -l urls.txt", type=str)
args = parser.add_argument("-o", "--output", help="Specify output file, example: -o outputs.txt")
args = parser.add_argument("-t", "--thread", help="Specify threads number, example: -t 2", type=int)

args = parser.parse_args()

def main():

    without_duplicates = remove_duplicates(args.list)
    urls_params = check_params(without_duplicates)
    urls_parsed = parser_urls(urls_params)

    if args.thread:
        check_vuln(urls_parsed, 1)
    else:
        check_vuln(urls_parsed, 0)

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
    for url in urls:
        try:
            f = furl(url)
            for payload in file_read:
                payload = payload.replace("{domain}", f.netloc)
                for args in f.args:
                    f.args[args] = payload
                else:
                    result.append(unquote(f.url))
        except:
            continue
    return result

def req_thread(url):
    try:
        req = requests.get(url, headers=HEADERS, timeout=10)
    except:
        pass
    if req.history:
        return True, url, req.url

def check_vuln(url_list, thread):
    if thread:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.thread) as executor:
            futures = [executor.submit(req_thread, url) for url in url_list]
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
    else:
        for url in url_list:
            try:
                req = requests.get(url, headers=HEADERS, timeout=10)
            except:
                continue
            if req.history:
                    if args.output:
                        try:
                            file_write = open(args.output, "a").write(f"{url} -> \033[92m{req.url}\033[00m\n")
                        except:
                            continue
                    print(f"Open redirect founded: {url} -> \033[92m{req.url}\033[00m")
            else:
                continue

if __name__ == "__main__":
    main()