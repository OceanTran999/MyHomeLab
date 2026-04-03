In the Javascript file code, in line 26, I use the code to reflect the user's input without checking whether it is secured or not.
This is called a DOM-based XSS, which the attacker abuses the DOM to change the benign elements into the malicious elements such as creating a malicious URL and treating users to click it.
First I will test my payload with `document.write()", and here is the output of my input:

<img width="1472" height="597" alt="DOM-XSS_test" src="https://github.com/user-attachments/assets/5f472981-6427-4134-aa39-3921b4d01abc"/>


Finally, I try to add the malicious URL:

<img width="1501" height="327" alt="DOM-XSS_link" src="https://github.com/user-attachments/assets/be5507d4-3cdf-443f-8390-02f4aff3108b"/>
