# mysslstrip

mysslstrip is a Python-based proof of concept showing how to MITM
MySQL traffic and strip SSL/TLS, as per [CVE-2015-3152](http://www.openwall.com/lists/oss-security/2015/04/29/4).

## Usage

`mysslstrip.py \[-h\] \[-p LISTEN\_PORT\] \[-i LISTEN\_INTERFACE\] dest`

## Additional Information


**Is this a real vulnerability?**

Yes! Encrypt all the things. Allowing opportunistic degradation of encryption is pretty poor practice.

**Patch?**

It's been fixed in [MySQL 5.7.3](http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-3.html) ... but the security
patch hasn't been backported to any other version, so if you're on 5.6 like 99.99% of the Internet is, you're out of
luck unless you switch to the 5.7 "preview release".

Created by [Adam Goodman](https://twitter.com/akgood) of [Duo Labs](https://labs.duosecurity.com).

**Inquiries?**

PR Inquiries: [this.is.a.really.big.deal@duosecurity.com](mailto:this.is.a.really.big.deal@duosecurity.com)

Technical Inquiries: [this.isnt.a.big.deal.but.you.should.still.patch@duosecurity.com](mailto:this.isnt.a.big.deal.but.you.should.still.patch@duosecurity.com)

Twitters: [@duo\_labs](https://twitter.com/duo_labs)

### References

[http://www.openwall.com/lists/oss-security/2015/04/29/4](http://www.openwall.com/lists/oss-security/2015/04/29/4)
[http://www.ocert.org/advisories/ocert-2015-003.html](http://www.ocert.org/advisories/ocert-2015-003.html)
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3152](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3152)
