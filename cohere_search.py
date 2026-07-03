#!/usr/bin/env python3
import sys,json,os,urllib.request
K=os.environ.get("COHERE_API_KEY","")
def rerank(q,docs,n=5):
 p=json.dumps({"model":"rerank-v3.5","query":q,"documents":docs,"top_n":n,"return_documents":True}).encode()
 r=urllib.request.Request("https://api.cohere.com/v2/rerank",data=p,headers={"Authorization":f"Bearer {K}","Content-Type":"application/json"})
 with urllib.request.urlopen(r) as x:return json.loads(x.read())
def search(q,k=5):
 w=os.environ.get("MIU_SEARCH_WEBHOOK","")
 if not w:raise ValueError("MIU_SEARCH_WEBHOOK not set")
 p=json.dumps({"query":q,"top_k":k}).encode()
 r=urllib.request.Request(w,data=p,headers={"Content-Type":"application/json"})
 with urllib.request.urlopen(r) as x:return json.loads(x.read())
if __name__=="__main__":
 q=" ".join(sys.argv[1:]) or "fractal dimension"
 print(json.dumps(search(q),indent=2,ensure_ascii=False))
