# Secure Framework

A modular security framework for Ruby on Rails applications, providing reusable secure components following "secure by default" principles.

## Design Rationale

This framework is implemented as a Ruby gem with Rails generators rather than a Rails Engine for several key reasons:

1. **Ease of Integration**: Generators allow for flexible integration into existing applications without complex mounting or namespace concerns.
2. **Customization**: Users can easily modify generated files to suit their specific needs.
3. **Incremental Adoption**: Components can be added gradually without requiring a full framework commitment.
4. **Simplified Development**: Gem development is more straightforward for our initial focus on core security components.

## Phase 1: Secure Authentication

The first available component provides secure authentication based on Devise, with:

- Secure password storage (bcrypt)
- Session management
- Account locking
- Customizable views
- Built-in protection against common vulnerabilities

## Installation & Integration

Add this line to your application's Gemfile:
gem 'secure_framework'

Then execute:
bundle install

Run the installation generator:
rails generate secure_framework:install

Apply the database migrations:
rails db:migrate

## Usage

To protect a controller, add:
before_action :authenticate_user!

Example:
class DashboardController < ApplicationController
  before_action :authenticate_user!
  
  def index
    # Only accessible by authenticated users
  end
end

## Testing
The demo app includes RSpec feature tests that verify:

- User registration
- Session management
- Access control

Run tests with:
bundle exec rspec


