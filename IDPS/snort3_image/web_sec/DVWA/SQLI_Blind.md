This challenge will delete the `die()` function so that the target server will not return the error message from SQL Server. Which will make more challenges for attackers to exploit the web app.

# Low and Hard level
If the target server does not have errors, then we just need to abuse the power of logics in SQL to exploit the server. Payload is `1' OR 1=1;#`. I tried to use `--` but it did not work, but it worked with `#`.

# Medium level
Payload is `1' OR 1=1;(#/--)`