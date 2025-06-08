# Secure Framework

A modular security framework for Ruby on Rails applications, providing reusable secure components following "secure by default" principles.

## Design Rationale

This framework is implemented as a Ruby gem with Rails generators rather than a Rails Engine for several key reasons:

1.  **Ease of Integration**: Generators allow for flexible integration into existing applications without complex mounting or namespace concerns.
2.  **Customization**: Users can easily modify generated files to suit their specific needs.
3.  **Incremental Adoption**: Components can be added gradually without requiring a full framework commitment.
4.  **Simplified Development**: Gem development is more straightforward for our initial focus on core security components.

## Security Components

### Phase 1: Secure Authentication (Devise)

The first available component provides secure authentication based on **Devise**, with:

-   Secure password storage (bcrypt).
-   **Strong Password Policy**: Automatically enforces a **12-character minimum** password length upon installation.
-   **Account Lockout**: Mitigates brute-force attacks by locking accounts after multiple failed attempts.
-   **Password Recovery**: Allows users to securely reset their password.
-   Session management and protection against CSRF attacks.

### Phase 2: Granular Authorization (Pundit)

The second component integrates **Pundit** to manage permissions, enabling fine-grained control over what an authenticated user is allowed to do.

-   **Clear Permission Policies**: Authorization logic is centralized in simple, easy-to-understand `Policy` classes.
-   **Automatic Setup**: The generator installs and configures Pundit in the `ApplicationController`, making it ready to use.
-   **Controller and View-Level Security**: Allows for easy protection of controller actions and conditionally rendering UI elements.

## Installation & Integration

Add this line to your application's Gemfile:
`gem 'secure_framework'`

Then execute:
`bundle install`

Run the installation generator to set up Devise (with secure defaults) and Pundit:
`rails generate secure_framework:install`

Apply the database migrations:
`rails db:migrate`

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

Once a user is authenticated, Pundit helps you manage their permissions.

**1. Protecting Controller Actions:**

Use the `authorize` method in your controller actions to enforce permission policies.

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

## Automatic Security Features

The `secure_framework:install` generator automatically configures your application with the following security-by-default settings:

1.  **Strong Password Policy**: Enforces a minimum password length of 12 characters. This is configured in `config/initializers/devise.rb`.

2.  **Account Locking**: Enabled by default to mitigate brute-force attacks.
    * Accounts are locked after **5 failed login attempts**.
    * The lock lasts for **30 minutes**.
    * Configuration can be found in `config/initializers/devise.rb`.

3.  **Secure Key Management**: The generator helps you move Devise's `secret_key` to the encrypted `config/credentials.yml.enc` file, preventing it from being exposed in your repository.

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

### Running the Test Suite

To run the full test suite, clone the `demo_app` repository, install the dependencies (`bundle install`), and execute:
```bash
bundle exec rspec
```

