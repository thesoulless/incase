# InCase
InCase save your secrets for a friend, so they can use in case
it in case you went "missing".

[![Deploy to DO](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/{REPO-OWNER}/{REPO-NAME}/tree/{BRANCH-NAME})

## How it works
It encodes your provided note with your given password using AES (Rijndael) and returns
a targetURL. The key argument should be the AES key, either 16, 24, or 32 bytes to 
select AES-128, AES-192, or AES-256.

You share the URL and the password with your friend/family. If you came
back and the targetURL was never called then you don't need to change your passwords.  

InCase intentionally does not log anything about your key/data.

## Why?
Everytime I'm going on a long trip, long flight, cruise, etc. I share
some of my passwords with a close friend, in case I die or went missing.

You may ask why a dead man should care about his accounts? In my case there
are some people who (to some extent) depend on me to sorting some of their digital
stuff around.

From another view point, maybe some day my friend/family would be able to ~~replicate~~
mimic "me" with all data there is and can have a chat with me.

> Ray Kurzweil entered the chat...
