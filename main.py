import argparse
import requests
from furl import furl
from urllib.parse import unquote


parser = argparse.ArgumentParser()

args = parser.add_argument("-u", "--url", help='Set url, example: -u https://example.com/?param=value', type=str)
args = parser.add_argument("-l", "--list", help="Specify file with urls, example: -l urls.txt", type=str)
args = parser.add_argument("-o", "--output", help="Specify output file, example: -o outputs.txt")

args = parser.parse_args()

def main():
    without_duplicates = remove_duplicates(args.list)
    urls_params = check_params(without_duplicates)
    urls_parsed = parser_urls(urls_params)
    #check_vuln(urls_parsed)

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

def check_vuln(url_list):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"}
    for url in url_list:
        try:
            req = requests.get(url, headers=headers, timeout=10)
        except:
            continue
        if req.history:
            if args.output:
                file_write = open(args.output, "a").write(f"{url} -> \033[92m{req.url}\033[00m\n")
            print(f"Open redirect founded: {url} -> \033[92m{req.url}\033[00m")
        else:
            continue

if __name__ == "__main__":
    main()
