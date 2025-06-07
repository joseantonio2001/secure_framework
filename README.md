# Secure Framework

A modular security framework for Ruby on Rails applications, providing reusable secure components following "secure by default" principles.

## Design Rationale

This framework is implemented as a Ruby gem with Rails generators rather than a Rails Engine for several key reasons:

1.  **Ease of Integration**: Generators allow for flexible integration into existing applications without complex mounting or namespace concerns.
2.  **Customization**: Users can easily modify generated files to suit their specific needs.
3.  **Incremental Adoption**: Components can be added gradually without requiring a full framework commitment.
4.  **Simplified Development**: Gem development is more straightforward for our initial focus on core security components.

## Phase 1: Secure Authentication

The first available component provides secure authentication based on Devise, with:

-   Secure password storage (bcrypt).
-   **Strong Password Policy**: Automatically enforces a **12-character minimum** password length upon installation.
-   **Account Lockout**: Mitigates brute-force attacks by locking accounts after multiple failed attempts.
-   **Password Recovery**: Allows users to securely reset their password.
-   Session management and protection against CSRF attacks.
-   Customizable views for easy integration.

## Installation & Integration

Add this line to your application's Gemfile:
`gem 'secure_framework'`

Then execute:
`bundle install`

Run the installation generator to set up Devise with secure defaults:
`rails generate secure_framework:install`

Apply the database migrations:
`rails db:migrate`

## Usage

To protect a controller, add the `before_action` filter provided by Devise:
`before_action :authenticate_user!`

Example:
```ruby
class DashboardController < ApplicationController
  before_action :authenticate_user!
  
  def index
    # Only accessible by authenticated users
  end
end
```

## Automatic Security Features

The `secure_framework:install` generator automatically configures your application with the following security-by-default settings:

1.  **Strong Password Policy**: Enforces a minimum password length of 12 characters. This is configured in `config/initializers/devise.rb`.

2.  **Account Locking**: Enabled by default to mitigate brute-force attacks.
    * Accounts are locked after **5 failed login attempts**.
    * The lock lasts for **30 minutes**.
    * Configuration can be found in `config/initializers/devise.rb`.

3.  **Secure Key Management**: The generator helps you move Devise's `secret_key` to the encrypted `config/credentials.yml.enc` file, preventing it from being exposed in your repository.

## Aplicación de Demostración (demo_app)

Para ver una implementación completa y funcional de este framework, puedes explorar la aplicación de demostración. Esta aplicación sirve como un ejemplo práctico de integración y es la base sobre la cual se ejecuta la suite de pruebas de seguridad.

➡️ Repositorio de la Demo: https://github.com/joseantonio2001/demo_app

## Testing

The demo app includes a comprehensive suite of RSpec feature tests to verify the core security functionalities. This ensures that the features configured by the generator work as expected.

The test suite covers:

-   **User Registration**: Verifies successful sign-up and handles invalid data.
-   **Session Management**: Confirms users can log in and log out correctly.
-   **Access Control**: Ensures protected areas are only accessible to authenticated users.
-   **Account Lockout**: Tests that a user's account is locked after the configured number of failed login attempts.
-   **Password Recovery**: Validates the full password reset flow, from email request to successful password change.

Run the full test suite with:
`bundle exec rspec`


