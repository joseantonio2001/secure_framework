# Secure Framework

A modular security framework for Ruby on Rails applications, providing reusable secure components following "secure by default" principles.

## Design Rationale

This framework is implemented as a Ruby gem with Rails generators rather than a Rails Engine for several key reasons:

1.  **Ease of Integration**: Generators allow for flexible integration into existing applications without complex mounting or namespace concerns.
2.  **Customization**: Users can easily modify generated files to suit their specific needs.

## Security Components

### Phase 1: Identity & Access Management (IAM)

This component establishes a solid foundation for knowing who a user is and what they are allowed to do.

- **Secure Authentication (Devise)**: Provides a robust and secure login system.
- **Granular Authorization (Pundit)**: Enables fine-grained permission policies to control authenticated user actions.

### Phase 2: Data & Input Protection

This component focuses on protecting the integrity of the data handled by the application.

- **Input Validation & Sanitization (Sanitize)**: Protects the application from Cross-Site Scripting (XSS) attacks by sanitizing all user-provided input.
- **Secure Output Encoding & XSS Prevention (CSP)**: Complements input sanitization by providing a critical defense on the output layer. It instructs the browser to block and report a wide range of injection attacks, serving as a powerful final backstop.

### Phase 3: Application Security Hardening

This group of components hardens the application's configuration and communication protocols to mitigate a broad range of common attacks.

- **Security Headers Management (SecureHeaders)**: Automatically applies crucial HTTP security headers to every response to protect against attacks like Clickjacking, MIME-type sniffing, and information leakage.
- **Reinforced CSRF Protection**: Ensures Rails' built-in defense against Cross-Site Request Forgery is configured in its strictest mode, aborting malicious requests immediately.

### Phase 4: Secure Development Operations (SecDevOps)

This component focuses on integrating security practices directly into the development and operations workflow.

- **Secure Secrets Management**: Guides the user in setting up and using Rails' encrypted credentials, ensuring no secret keys are ever committed to version control.
- **Dependency Auditing**: Integrates automated vulnerability scanning for all project dependencies (gems), ensuring the application's supply chain is secure.

## Installation & Integration

Add this line to your application's Gemfile:
`gem 'secure_framework'`

Then execute:
`bundle install`

Run our installation generator. This command will install and configure all security components if it detects they have not yet been configured in your application:
`rails generate secure_framework:install`

Apply the necessary database migrations (for Devise's User model):
`rails db:migrate`

Follow post-install instructions. The generator will prompt you with any required manual steps, such as editing your encrypted credentials to add secret keys.
`bin/rails credentials:edit`

## Usage

### Authentication (Who can access?)

To protect a controller and require a user to be logged in, use the `before_action` filter provided by Devise:
`before_action :authenticate_user!`

**Example:**
```ruby
class DashboardController < ApplicationController
  before_action :authenticate_user!
  
  def index
    # Only accessible by authenticated users
  end
end
```

### Authorization (What can a user do?)

**1. Protecting Controller Actions:**

Once a user is authenticated, use Pundit's `authorize` method in your controller actions to enforce permission policies.

```ruby
# app/controllers/posts_controller.rb
class PostsController < ApplicationController
  def update
    @post = Post.find(params[:id])
    authorize @post # Raises an error if the user is not allowed by the PostPolicy
    
    # ... update logic
  end
end
```
**2. Conditionally Rendering in Views:**

Use the `policy` helper in your views to show or hide UI elements based on the current user's permissions.

```erb
<!-- app/views/posts/show.html.erb -->

<h1><%= @post.title %></h1>
<p><%= @post.content %></p>

<%# The edit link is only shown if the policy allows it %>
<% if policy(@post).edit? %>
  <%= link_to 'Edit', edit_post_path(@post) %>
<% end %>
```

### Input Sanitization (How to clean user data?)

To protect against XSS attacks, you should sanitize all data that comes from a user before saving it. The framework provides a strict, "plain text only" default configuration.

**Example Implementation in a Controller:**

```ruby
class PostsController < ApplicationController
  def create
    @post = current_user.posts.build(post_params)

    # Apply sanitization to text fields before authorization and saving
    @post.title = sanitize_input(@post.title)
    @post.content = sanitize_input(@post.content)
    
    authorize @post

    # ... save logic ...
  end

  private

  def post_params
    params.require(:post).permit(:title, :content)
  end

  def sanitize_input(dirty_data)
    # Uses the framework's default configuration from the initializer
    return nil unless dirty_data
    Sanitize.fragment(dirty_data, Sanitize::Config::SECURE_FRAMEWORK)
  end
end
```

### Accessing Secrets (How to use credentials?)

All secrets, such as API keys or external service passwords, should be stored in the encrypted `config/credentials.yml`.enc file. You can access them in your application using `Rails.application.credentials`. Using `.dig()` is recommended as it safely returns `nil` if a key is not found, preventing errors.

**Example Implementation in a Controller:**

```ruby
class DashboardController < ApplicationController
  before_action :authenticate_user!

  def index
    # Safely access the api_key from the encrypted credentials
    @api_key = Rails.application.credentials.dig(:api_key)
  end
end
```

  **⚠️ Important Security Note**: The example above shows how to load a secret into a controller variable. This variable should be used for **back-end operations only** (e.g., authenticating with a third-party API). **Never** render raw secrets in your HTML views, as this would expose them to the user and defeat the purpose of using encrypted credentials.

### Dependency Auditing (How to check for vulnerabilities?) 

The framework provides two ways to check for known vulnerabilities in your project's dependencies:

  1. **Rake Task (for command-line and CI/CD):**

  The installation generator creates a Rake task that scans your `Gemfile.lock`. To run it, execute the following command from your terminal:

  ```bash
  rake dependency_audit:check
  ```

  This task is ideal for integration into a CI/CD pipeline, as it will exit with a non-zero status code (failing the build) if any vulnerabilities are found.

  2. **Web Interface (in the [demo application](https://github.com/joseantonio2001/demo_app))**:

  For manual checks, an authenticated user can visit the Dependency Audit page in the dashboard to see a real-time report of any vulnerabilities. 

## Automatic Security Features

The `secure_framework:install` generator automatically configures your application with the following security-by-default settings:

1.  **Strong Password Policy**: Enforces a minimum password length of 12 characters. This is configured in `config/initializers/devise.rb`.

2.  **Account Locking**: Enabled by default to mitigate brute-force attacks.
    * Accounts are locked after **5 failed login attempts**.
    * The lock lasts for **30 minutes**.
    * Configuration can be found in `config/initializers/devise.rb`.

3.  **Secure Credentials & Key Management**:
    * The generator ensures `config/master.key` is added to your `.gitignore` file, which is critical to prevent leaking the key that unlocks all your secrets.
    * It migrates Devise's `secret_key` to be loaded from `config/credentials.yml.enc`, removing it from the standard initializer.
    * It intelligently guides the user on next steps, such as running `bin/rails credentials:edit` to manage application secrets.    

4.  **Secure Key Management**: The generator helps you move Devise's `secret_key` to the encrypted `config/credentials.yml.enc` file, preventing it from being exposed in your repository.

5. **Strict Input Sanitization**: 
    * Creates an initializer at `config/initializers/sanitize.rb`.
    * By default, this policy **strips all HTML tags** from user input, allowing only plain text. This effectively prevents XSS attacks.
    * This configuration can be customized by the developer to allow specific HTML tags if needed.

6. **Strict Content Security Policy (CSP)**: 
    * Creates a robust policy at `config/initializers/content_security_policy.rb`.
    * Blocks unsafe inline scripts and styles, preventing XSS and UI defacement attacks.
    * Restricts resource loading (images, fonts, etc.) to the application's own origin (`'self'`) or other secure `https:` sources.
    * Uses `nonces` for compatibility with Rails 7's internal scripts (Turbo/Importmaps).
    * Includes specific `sha256` hashes to securely allow necessary framework features (like `turbo_confirm`) to function without weakening the overall policy.

7. **Comprehensive Security Headers**:
    * Uses the `secure_headers` gem to create a policy at `config/initializers/secure_headers.rb`.
    * Applies headers like `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` to defend against a wide array of browser-based attacks.
    * It is configured to work harmoniously with the native Rails CSP, avoiding conflicts.

8. **Reinforced CSRF Protection**:
    * Ensures all non-GET requests are verified against a unique CSRF token.
    * Injects `protect_from_forgery with: :exception, prepend: true` into the `ApplicationController`.
    * The `with: :exception` policy is stricter than the default, as it halts the entire request flow by raising an exception, making attacks immediately visible.
    * The `prepend: true` option guarantees this security check runs before any other controller logic, ensuring its effectiveness even in applications using frameworks like Turbo.
    * The generator is idempotent and will not modify the controller if a CSRF protection rule already exists.

9. **Automated Dependency Auditing**:
    * The generator creates an idempotent Rake task at `lib/tasks/dependency_audit.rake` using the `bundler-audit` gem.
    * This task scans your `Gemfile.lock` against a database of known vulnerabilities.
    * It is designed for CI/CD integration and will fail the build process if insecure dependencies are found, enforcing a secure development lifecycle.

## Demonstration Application & Testing

To verify that the framework functions as expected, validation is performed through a demonstration application (`demo_app`) that integrates the gem. **All security tests are located and run within this application**, serving as a real-world use case.

➡️ **Demo Repository:** [https://github.com/joseantonio2001/demo_app](https://github.com/joseantonio2001/demo_app)

### Test Coverage

The `demo_app`'s test suite, written with **RSpec** and **Capybara**, verifies the following functionalities:

#### Authentication Tests
-   **User Registration**: Successful sign-up and invalid data handling.
-   **Session Management**: Correct user login and logout.
-   **Access Control**: Protected areas are only accessible to authenticated users.
-   **Account Lockout**: The account is locked after the configured number of failed login attempts.
-   **Password Recovery**: The full password reset flow works as expected.

#### Authorization Tests
-   **Guest Access**: Unauthenticated users are redirected from protected URLs (e.g., `/posts/new`) to the login page.
-   **Unauthorized Access**: An authenticated user cannot access another user's resources (e.g., trying to edit another's post) and is redirected with an alert message.
-   **Authorized Access**: Resource owners can perform permitted actions (creating, editing, and deleting their own posts).

#### Input Sanitization Tests
-   HTML tags (e.g., `<h1>`, `<b>`) are stripped from user input before being saved to the database.
-   Malicious script tags (`<script>`) are completely removed to prevent XSS attacks.
-   Sanitization is correctly applied to all relevant fields (e.g., title and content) when creating and updating a resource.

#### Content Security Policy (CSP) Tests
-   Asserts that the `Content-Security-Policy` HTTP header is present and sent with every response.
-   Confirms that the policy is strict and does not contain the dangerous `'unsafe-inline'` directive for scripts or styles.
-   Verifies that the specific, secure `sha256` hashes for Turbo functionality are included in the policy.

#### Security Headers Tests
-   Confirms that key security headers (`X-Frame-Options`, `X-Content-Type-Options`, etc.) are present in the application's responses with the correct secure values.  

#### CSRF Protection Tests

-   Verifies that `POST` requests without a valid CSRF token are rejected with an `unprocessable_entity` (422) status code.
-   Confirms that a valid request can successfully create a resource. This test bypasses the token verification via a stub (`allow_any_instance_of`) to work around a known session persistence issue in the RSpec request spec environment, allowing the controller's internal "happy path" logic to be tested in isolation.   

#### Secure Credentials Tests
-   Verifies that a secret stored in Rails Credentials can be successfully loaded in the controller and displayed on a protected page.
-   Confirms that the test suite can run without the actual master.key by correctly stubbing Rails.application.credentials. 
-   Checks that the UI handles cases where the secret is missing gracefully.

#### Dependency Audit Tests
-   Verifies that the Dependency Audit page renders correctly for an authenticated user.
-   Tests the "no vulnerabilities found" scenario, checking for the success message.
-   Tests the "vulnerability found" scenario by using a mock scanner to inject a fake vulnerability, and confirms that the details are displayed correctly in the results table.

### Running the Test Suite

To run the full test suite, clone the `demo_app` repository, install the dependencies (`bundle install`), and execute:
```bash
bundle exec rspec
```

