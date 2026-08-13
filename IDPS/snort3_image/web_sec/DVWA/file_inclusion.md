# Low level
Payload = `../../../../../<name of target file>`

# Mid level
Reading the code of this challenge, we can see they add some validation.
```
// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );
```

Therefore, my payload of this challenge is: `.../...//../.../...//../.../...//../.../...//../.../...//../.../...//../.../...//../.../...//../etc/passwd`. The idea is:
- `.../` will return to `.`
- `/../` will return to `/`

# High level
The code in this challenge is a little bit harder.
```
// Input validation
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
	// This isn't the page we want!
	echo "ERROR: File not found!";
	exit;
}
```

According to [Protcols for File Inclusion](https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#more-protocols) and [File Protocol](https://stackoverflow.com/questions/3616795/what-is-the-difference-between-file-file-file), we see that the filter will only accept the `file{1..3}.php` and `include.php`. However, there's a problem in checking `file*` because we can use the `file://` protocol to call a local file of the target server. So the payload is: `file:///etc/passwd` (:/// is used for calling the root directory in Linux)