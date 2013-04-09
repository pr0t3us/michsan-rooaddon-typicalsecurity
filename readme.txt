This is a Spring Roo Addon which helps developer quick setup Typical Security setup for their Spring Roo Project.

Note: This project is based on https://code.google.com/p/spring-roo-addon-typical-security. But, as it changed a lot, I recreated.

Features
--------
- Admin can:
	+ Manage users, roles and assigning user roles for security.
	+ Disable account.

- User can
	+ Authenticate with JPA based authentication provider.
	+ Change password.
	+ Edit his/her profile.

- Guest can
	+ Recover his/her password via email.
	+ Register as new user. This action uses recaptcha and sends activation email (by default it, is triggered by admin checking enabled).
	+ Activate account.


Future features
---------------
- Add Entities to track User activities and Lock User functionality
- Add facility to allow user to login using gmail, yahoo, facebook, twitter logins. Also allow login using OpenId
- Allow OAuth, Basic and Token based authentication using the User name and password for third party Authentication


Quick start
-----------
project --topLevelPackage id.web.michsan.myroo
jpa setup --provider ECLIPSELINK --database HYPERSONIC_IN_MEMORY
web mvc setup

osgi start --url file:///absolute/path/to/michsan.rooaddon.typicalsecurity-1.2.3-SNAPSHOT.jar
typicalsecurity setup --entityPackage ~.domain.security --controllerPackage ~.web.security


Email configuration
-------------------
The default email configuration is for GMail with TLS connection.

You can use set all properties in javaMailProperties only.

For TLS:
mail.smtp.host = smtp.gmail.com
mail.smtp.auth = true;
mail.smtp.starttls.enable = true
# mail.smtp.port = 587

For SSL:
mail.smtp.host = smtp.gmail.com
mail.smtp.auth = true
mail.smtp.ssl.enable=true
# mail.smtp.port = 465

