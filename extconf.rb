#!/usr/bin/env ruby
require 'mkmf'
dir_config("iptools")
have_library("resolv")
create_makefile("IPTools")
