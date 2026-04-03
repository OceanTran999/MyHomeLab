In the Javascript file code, in line 26, I use the code to reflect the user's input without checking whether it is secured or not.
This is called a DOM-based XSS, which the attacker abuses the DOM to change the benign elements into the malicious elements such as creating a malicious URL and treating users to click it.
First I will test my payload with `document.write()", and here is the output of my input:




Finally, I try to add the malicious URL:

