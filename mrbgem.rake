MRuby::Gem::Specification.new('mruby-generate-address') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Tetsuya'
  spec.summary = 'self-generate-adress'
  spec.add_dependency('mruby-onig-regexp', :github => 'mattn/mruby-onig-regexp'	)
  spec.add_dependency('mruby-digest', :git => 'https://github.com/iij/mruby-digest.git')
  spec.add_dependency('mruby-secure-random', :github => 'monochromegane/mruby-secure-random')
  spec.add_dependency('mruby-bignum',:git=>'https://github.com/chasonr/mruby-bignum.git')
end