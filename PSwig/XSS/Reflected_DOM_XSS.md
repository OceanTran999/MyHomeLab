The payload of this challenge is:

```
\"+alert()}//
```
Because the `XMLHttpRequest()` usually uses `JSON` data type. Therefore:
- The backslash `\"` is used for JSON escaped character.
- The `}` is used for close the JSON data sending to `search-result`.
- The double slash `//` is used for comment the remaining of the first legit JSON data, which is `"}`.
- We can also change the `+` with `-`.
- The final output of the responsed data from server will be:
```
{"results":[],

"searchTerm":"\\" alert()
}//"}
```
