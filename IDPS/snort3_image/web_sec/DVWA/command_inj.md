# Low and Mid level
- just adding `||` with command to execute shell command.

# High level
- The filter of this challenge is updated:
```
$substitutions = array(
		'||' => '',
		'&'  => '',
		';'  => '',
		'| ' => '',
		'-'  => '',
		'$'  => '',
		'('  => '',
		')'  => '',
		'`'  => '',
	);
```

The question is if we add `(2n+1)`(`n`:number of occurrences) `|`, will it consider like ` |`? For example, if we add `|||`, will our payload will be executed into ` |`? Therefore, the payload of this challenge is `|||id`.