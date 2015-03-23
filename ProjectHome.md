This is a Spring Roo Addon which helps developer quick setup Typical Security setup for their Spring Roo Project.

# Note #
This project is based on https://code.google.com/p/spring-roo-addon-typical-security. But, as it changed a lot, I recreated.

# Features #
# Admin can
  * Manage users, roles and assigning user roles for security.
  * Disable account.
# User can
  * Authenticate with JPA based authentication provider.
  * Change password.
  * Edit his/her profile.
# Guest can
  * Recover his/her password via email.
  * Register as new user. This action uses recaptcha and sends activation email (by default it, is triggered by admin checking enabled).
  * Activate account.