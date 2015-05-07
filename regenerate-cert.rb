#!/usr/bin/env ruby

require 'net/http'
require 'openssl'
require 'openssl-extensions/all'
require 'uri'
require 'optparse'
require 'ostruct'
require 'resolv'
require 'logger'

def parse_options(args)
  options = OpenStruct.new

  options.server = 'localhost'
  options.outputdir = Dir.pwd
  options.certname = 'unset'
  options.port = '443'
  options.sans = true
  options.sans_auto = true
  options.sans_append = [ ]
  options.sans_remove = [ ]
  options.logfile = 'cert-tools.log'

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

    opts.on("-p", "--port PORT", "Remote Port") do |p|
      options.port = p
    end

    opts.on("-n", "--certname CERTNAME", "Cert Name") { |n| options.certname = n }

    opts.on("--no-sans", "SANS") { |sans| options.sans = false }

    opts.on(
      "--san SAN_NAME",
      "Append an additional SAN Name"
    ) {
      |san| options.sans_append.push(san)
    }

    opts.on(
      "--no-sans-auto",
      "Do not automatically add SANS that exist on the current cert"
    ) { |auto|
      options.sans_auto = false
    }

    opts.on(
      "--san-remove SAN_NAME",
      "Remove a SAN from the certificate request. Only useful when --no-sans-auto is not specified"
    ) { |remove|
      options.sans_remove.push(remove)
    }

    opts.on("--replace-cn",
            "Replace CN with the name specified by the -n flag") { |replace|
      options.replace_cn = true
    }
  end

  opt_parser.parse!(args)
  #options.certname = options.server if options.certname == 'unset'
  options
end

def read_key(keyfile)
  file = File.open(keyfile,'r')
  key = OpenSSL::PKey::RSA.new(file.read)
  file.close
  return key
end

def generate_key(keyfile)
  key = OpenSSL::PKey::RSA.new 2048
  file = File.new(keyfile,'w')
  file.write(key)
  file.close
  return key
end


options = parse_options(ARGV)

logger = Logger.new(options.logfile)
logger.level = Logger::INFO

https = Net::HTTP.new(options.server, options.port)
https.use_ssl = true
https.verify_mode = OpenSSL::SSL::VERIFY_NONE

@certificate = nil

https.start { |http| @certificate = https.peer_cert }

options.certname = @certificate.subject.common_name if options.certname == 'unset'

keyfile = "#{options.outputdir}/#{options.certname}.key"
if File.exist?(keyfile)
  logger.info("key exists -- reading from #{keyfile}")
  key = read_key keyfile
else
  logger.info("key does not exists -- generating key in #{keyfile}")
  key = generate_key keyfile 
end

# modify the subject if we were passed the --replace-cn flag and the -n flag
# is set.
subject = OpenSSL::X509::Name.new(@certificate.subject)
subject_a = subject.to_a.map do |itm|
  itm[1] = options.certname if itm[0] == 'CN'
  itm = itm
end
subject = OpenSSL::X509::Name.new(subject_a) if options.certname != 'unset' and options.replace_cn

request = OpenSSL::X509::Request.new
request.version = 0
request.subject = subject
request.public_key = key.public_key

exts = [
  ["basicConstraints", "CA:FALSE", false],
  ["keyUsage", "Digital Signature, Non Repudiation, Key Encipherment",false],
]

if options.sans
  sans = [ ]
  if options.sans_auto
    @certificate.sans.each do |alt|
      sans << "DNS:#{alt}" unless options.sans_remove.include?(alt)
    end
  end
  options.sans_append.each do |alt|
    sans << "DNS:#{alt}"
  end
  exts << [ "subjectAltName", sans.join(','), false ]
end

ef = OpenSSL::X509::ExtensionFactory.new
exts = exts.collect { |e| ef.create_extension(*e) }
attrval = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
attrs = [
  OpenSSL::X509::Attribute.new("extReq", attrval),
  OpenSSL::X509::Attribute.new("msExtReq", attrval)
]
attrs.each { |attr| request.add_attribute(attr) }
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
