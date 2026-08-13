Here's the source code in DOM XSS challenge:

```
<script>
	if (document.location.href.indexOf("default=") >= 0) {
		var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
		document.write("<option value='" + lang + "'>" + $decodeURI(lang) + "</option>");
		document.write("<option value='' disabled='disabled'>----</option>");
	}
	    
	document.write("<option value='English'>English</option>");
	document.write("<option value='French'>French</option>");
	document.write("<option value='Spanish'>Spanish</option>");
	document.write("<option value='German'>German</option>");
</script>
```

# Low level
The vulnerable code is `document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");`, which will take the value of the parameter `default` in the URI, so we just need to add `<script>alert()</script>` behind the `default=`.

# Mid level
At first I tried to all of steps to add the `<img>` to the URL, but it did not work. However, after reading the help, I realized that I forgot to close the `<select>` so the final payload is: `English</option></select><img src=1 onerror=alert('XSS')>`

# High level

```
// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
} 
```

My idea is that to create the parameter `default` 2 times so that the first value of this parameter, which is the specific language, will be checked by the server, while the second value which is the malicious JS, will be executed by attacker. And somehow it's worked :)
Final payload: `?default=English&?default=<script>alert(1);</script>`

The answer has another way that the string after the `#` symbol will not be read by the server, so other payload is: `English#<script>alert('XSS')</script>`