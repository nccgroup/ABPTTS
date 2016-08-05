# A Black Path Toward The Sun
(TCP tunneling over HTTP for web application servers)

https://www.blackhat.com/us-16/arsenal.html#a-black-path-toward-the-sun

Ben Lincoln, NCC Group, 2016

ABPTTS uses a Python client script and a web application server page/package[1]
to tunnel TCP traffic over an HTTP/HTTPS connection to a web application 
server. In other words, anywhere that one could deploy a web shell, one should
now be able to establish a full TCP tunnel. This permits making RDP, 
interactive SSH, Meterpreter, and other connections through the web 
application server.

The communication is designed to be fully compliant with HTTP standards, 
meaning that in addition to tunneling *in* through a target web application 
server, it can be used to establish an *outbound* connection through 
packet-inspecting firewalls.

A number of novel features are used to make detection of its traffic 
challenging. In addition to its usefulness to authorized penetration testers, 
it is intended to provide IDS/WPS/WAF developers with a safe, live example of
malicious traffic that evades simplistic regex-pattern-based signature models.

An extensive manual is provided in PDF form, and walks the user through a 
variety of deployment scenarios.

This tool is released under version 2 of the GPL.

[1] Currently JSP/WAR and ASP.NET server-side components are included.

Compare and contrast with:

- reGeorg (https://github.com/sensepost/reGeorg)

- HTTP tunnel for Node.js (https://github.com/johncant/node-http-tunnel)

