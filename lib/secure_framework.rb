# frozen_string_literal: true

require_relative "secure_framework/version"
require "devise"
require "pundit"
require "sanitize"
require "secure_headers"

module SecureFramework
  class Error < StandardError; end
  # Your code goes here...
end
