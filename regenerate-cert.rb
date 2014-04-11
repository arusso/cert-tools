#!/bin/env ruby

require 'net/http'
require 'openssl'
require 'openssl-extensions/all'
require 'uri'
require 'optparse'
require 'ostruct'
require 'resolv'

def parse_options(args)
  options = OpenStruct.new

  options.server = 'localhost'
  options.outputdir = Dir.pwd
  options.certname = 'unset'
  options.port = '443'

  opt_parser = OptionParser.new do |opts|
    opts.banner = "Usage: regenerate-cert.rb [options]"
    opts.on("-s", "--server SERVER", "Server to regenerate certificate for") do |s| 
      raise(Errno::ENOENT, "Could not resolv #{s}") unless Socket.gethostbyname(s)
      options.server = s
    end

    opts.on("-o", "--outputdir DIR", "Output Dir") do |o|
      raise(Errno::ENOENT, "Directory #{o} doesn't exist") unless File.directory?(o)
      options.outputdir = o 
    end

    opts.on("-p", "--port PORT", "Output Dir") do |p|
      options.port = p 
    end

    opts.on("-n", "--certname CERTNAME", "Cert Name") { |n| options.certname = n }
  end

  opt_parser.parse!(args)
  #options.certname = options.server if options.certname == 'unset'
  options
end

options = parse_options(ARGV)

https = Net::HTTP.new(options.server, options.port)
https.use_ssl = true
https.verify_mode = OpenSSL::SSL::VERIFY_NONE

@certificate = nil

https.start { |http| @certificate = https.peer_cert }

options.certname = @certificate.subject.common_name if options.certname == 'unset'

keyfile = "#{options.outputdir}/#{options.certname}.key"
if File.exist?(keyfile)
  puts "key exists, reading existing key..."
  file = File.open(keyfile,'r')
  key = OpenSSL::PKey::RSA.new(file.read)
  file.close
else
  puts "generating new key..."
  key = OpenSSL::PKey::RSA.new 2048 unless File.exist?(keyfile)
  file = File.new(keyfile,'w',0400)
  file.write(key)
  file.close
end

request = OpenSSL::X509::Request.new
request.version = 0
request.subject = @certificate.subject
request.public_key = key.public_key

exts = [
  ["basicConstraints", "CA:FALSE", false],
  ["keyUsage", "Digital Signature, Non Repudiation, Key Encipherment",false],
]
sans = [ ]
@certificate.sans.each do |alt|
  sans << "DNS:#{alt}"
end
exts << [ "subjectAltName", sans.join(','), false ]

ef = OpenSSL::X509::ExtensionFactory.new
exts = exts.collect { |e| ef.create_extension(*e) }
attrval = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
attrs = [
  OpenSSL::X509::Attribute.new("extReq", attrval),
  OpenSSL::X509::Attribute.new("msExtReq", attrval)
]
attrs.each { |attr| request.add_attribute(attr) }
#attrval = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(@certificate.extensions)])
#attrs = [
#  OpenSSL::X509::Attribute.new("extReq", attrval),
#  OpenSSL::X509::Attribute.new("msExtReq", attrval)
#]
#attrs.each { |attr| request.add_attribute(attr) }
request.sign(key, OpenSSL::Digest::SHA1.new)

csrfile = "#{options.outputdir}/#{options.certname}.csr"
csrhfile = "#{options.outputdir}/#{options.certname}.csrh"

# get rid of the old csr file if it's around
File.delete(csrfile) if File.exist?(csrfile)

file = File.new(csrfile, 'w',0400)
file.write(request)
file.close

File.delete(csrhfile) if File.exist?(csrhfile)
file = File.new(csrhfile, 'w',0400)
file.write(request.to_text)
file.close
