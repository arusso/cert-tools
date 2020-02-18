#!/usr/bin/env ruby

require 'net/http'
require 'openssl'
require 'openssl-extensions/all'
require 'uri'
require 'optparse'
require 'ostruct'
require 'resolv'
require 'logger'

VALID_KEY_SIZES = [ 2048, 4096, 8192 ]

def parse_options(args)
  options = OpenStruct.new

  options.server = 'localhost'
  options.outputdir = Dir.pwd
  options.cn = ''
  options.state = ''
  options.country = ''
  options.city = ''
  options.org = ''
  options.orgunit = ''
  options.port = '443'
  options.sans = true
  options.sans_auto = true
  options.sans_append = [ ]
  options.sans_remove = [ ]
  options.logfile = 'cert-tools.log'
  options.keyfile = ''
  options.keysize = 2048

  opt_parser = OptionParser.new do |opts|
    opts.banner = "Usage: regenerate-cert.rb [options]"
    opts.on("-s", "--server SERVER", "Server to regenerate certificate for") do |s| 
      raise(Errno::ENOENT, "Could not resolv #{s}") unless Socket.gethostbyname(s)
      options.server = s
    end

    opts.on("-o", "--output-dir DIR", "Output Dir") do |o|
      raise(Errno::ENOENT, "Directory #{o} doesn't exist") unless File.directory?(o)
      options.outputdir = o
    end

    opts.on("-p", "--port PORT", "Remote Port") do |p|
      options.port = p
    end

    opts.on("-n", "--cn CERTNAME", "Cert Name") { |n| options.cn = n }

    opts.on("--email-address EMAIL", "Subject email address") { |n| options.emailaddress = n }
    opts.on("--state STATE", "Subject state") { |n| options.state = n }
    opts.on("--city CITY", "Subject city") { |n| options.city = n }
    opts.on("--country COUNTRY", "Subject country") { |n| options.country = n }
    opts.on("--org ORG", "Subject organization") { |n| options.org = n }
    opts.on("--org-unit ORGUNIT", "Subject organization unit") { |n| options.orgunit = n }

    opts.on("--no-sans", "SANS") { |sans| options.sans = false }

    opts.on("--key-size SIZE", "Private Key size in bits for new keys.") do |size|
      size = size.to_i
      if not VALID_KEY_SIZES.include? size
        raise "Unacceptable key size #{size} specified!"
      end

      options.keysize = size.to_i if VALID_KEY_SIZES.include? size.to_i
    end

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

    opts.on("--update-subject",
            "Update subject if any of the values are changed") { |replace|
      options.update_subject = true
    }

    opts.on("--private-key-file KEYFILE", "Use existing private key file") { |keyfile|
      options.keyfile = keyfile
    }
  end

  opt_parser.parse!(args)
  options
end

def read_key(keyfile)
  file = File.open(keyfile,'r')
  key = OpenSSL::PKey::RSA.new(file.read)
  file.close
  return key
end

def generate_key(keyfile, size)
  key = OpenSSL::PKey::RSA.new size
  file = File.new(keyfile,'w',0400)
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

options.cn = @certificate.subject.common_name if options.cn == ''

if options.keyfile != ""
  if File.exist?(options.keyfile)
    keyfile = options.keyfile
  else
    logger.error("specified keyfile does not exist -- #{options.keyfile}")
    raise(Errno::ENOENT, "Specified private key #{options.keyfile} does not exist")
  end
else
  keyfile = "#{options.outputdir}/#{options.cn}.key"
end

if File.exist?(keyfile)
  logger.info("key exists -- reading from #{keyfile}")
  key = read_key keyfile
else
  logger.info("key does not exists -- generating key in #{keyfile}")
  key = generate_key keyfile
end

subject = OpenSSL::X509::Name.new(@certificate.subject)
# update our subject if --update-subject is specified
if options.update_subject
  subject_a = subject.to_a.map do |itm|
    itm[1] = options.cn if itm[0] == 'CN' and not options.cn.empty?
    itm[1] = options.emailaddress if itm[0] == 'emailAddress' and not options.emailaddress.empty?
    itm[1] = options.city if itm[0] == 'L' and not options.city.empty?
    itm[1] = options.state if itm[0] == 'ST' and not options.state.empty?
    itm[1] = options.country if itm[0] == 'C' and not options.country.empty?
    itm[1] = options.org if itm[0] == 'O' and not options.org.empty?
    itm[1] = options.orgunit if itm[0] == 'OU' and not options.orgunit.empty?
    itm = itm
  end
  subject = OpenSSL::X509::Name.new(subject_a)
end


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
  sans << "DNS:#{options.cn}"
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

csrfile = "#{options.outputdir}/#{options.cn}.csr"
txtfile = "#{options.outputdir}/#{options.cn}.txt"

# get rid of the old csr file if it's around
File.delete(csrfile) if File.exist?(csrfile)

file = File.new(csrfile, 'w',0400)
file.write(request)
file.close

File.delete(txtfile) if File.exist?(txtfile)
file = File.new(txtfile, 'w',0400)
file.write(request.to_text)
file.close
