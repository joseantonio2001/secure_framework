# frozen_string_literal: true

require_relative "lib/secure_framework/version"

Gem::Specification.new do |spec|
  spec.name = "secure_framework"
  spec.version = SecureFramework::VERSION
  spec.authors = ["José Antonio"]
  spec.email = ["jatorrescoca@gmail.com"]
  spec.summary = "Framework de seguridad para Ruby on Rails"
  spec.description = "Proporciona componentes seguros reutilizables para aplicaciones Rails"
  spec.homepage = "https://github.com/joseantonio2001/secure_framework"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  #spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Dependencias principales
  spec.add_dependency "rails", "~> 7.2.2"
  spec.add_dependency "devise", "~> 4.9.3"
  spec.add_dependency "pundit", "~> 2.3"
  spec.add_dependency "sanitize", ">= 6.0"
  spec.add_dependency "secure_headers", ">= 6.5"
  spec.add_dependency "bundler-audit", "~> 0.9.1"
  spec.add_dependency "lograge"

  # Dependencias para desarrollo
  spec.add_development_dependency "rspec-rails", "~> 6.1.0"
  spec.add_development_dependency "sqlite3", "~> 1.6.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
