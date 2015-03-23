# Quick start #
```
project --topLevelPackage id.web.michsan.myroo
jpa setup --provider ECLIPSELINK --database HYPERSONIC_IN_MEMORY
web mvc setup

osgi start --url file:///absolute/path/to/michsan.rooaddon.typicalsecurity-1.2.3-SNAPSHOT.jar
typicalsecurity setup --entityPackage ~.domain.security --controllerPackage ~.web.security
```

**OR**

```
project --topLevelPackage id.web.michsan.myroo
jpa setup --provider ECLIPSELINK --database HYPERSONIC_IN_MEMORY
web mvc setup

osgi start --url https://michsan-rooaddon-typicalsecurity.googlecode.com/files/michsan.rooaddon.typicalsecurity-1.2.3-SNAPSHOT.jar
typicalsecurity setup --entityPackage ~.domain.security --controllerPackage ~.web.security
```

# Email configuration #
The default email configuration is for GMail with TLS connection.

You can use set all properties in javaMailProperties only.

## For TLS ##
```
mail.smtp.host = smtp.gmail.com
mail.smtp.auth = true;
mail.smtp.starttls.enable = true
# mail.smtp.port = 587
```

## For SSL ##
```
mail.smtp.host = smtp.gmail.com
mail.smtp.auth = true
mail.smtp.ssl.enable=true
# mail.smtp.port = 465
```