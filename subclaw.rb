#!/usr/bin/env ruby
# =============================================================================
# SubClaw v1.5 - Fast Subdomain Recon Tool
# =============================================================================
# Quickly scan subdomains (from subfinder or --domain), check DNS, HTTP,
# archive URLs, and let you decide which ones are interesting.
#
# Developed by Zuhaib Ullah Baig
# GitHub: https://github.com/zuhaibullahbaig
# =============================================================================

require 'optparse'
require 'io/console'
require 'net/http'
require 'uri'
require 'open3'
require 'timeout'
require 'fileutils'
require 'securerandom'

# ====================== COLORS ======================
def c(text, code) = "\e[#{code}m#{text}\e[0m"

# ====================== COMMAND EXISTS ======================
def command_exists(cmd)
  system("command -v #{cmd} > /dev/null 2>&1")
end

# ====================== DOCTOR MODE ======================
def run_doctor
  puts c("\n=== SubClaw Doctor Check ===\n", 36)
  puts "Developed by Zuhaib Ullah Baig | https://github.com/zuhaibullahbaig\n\n"

  checks = {
    "Subdomain Discovery" => ["subfinder"],
    "DNS"                 => ["dig", "nslookup"],
    "URL History"         => ["waybackurls", "gau"],
    "HTTP"                => ["curl"],
    "Port Scan"           => ["masscan", "nmap"]
  }

  checks.each do |category, tools|
    available = tools.select { |t| command_exists(t) }
    status = available.any? ? c("✅ OK", 32) : c("⚠️ MISSING", 31)
    puts "#{category}: #{status} #{available.any? ? "(#{available.join(', ')})" : ''}"
  end

  puts "\nRun 'subclaw --help' for usage"
end

# ====================== UNIQUE FILENAME ======================
def unique_filename(base)
  filename = base
  counter = 1
  while File.exist?(filename)
    filename = base.sub(/\.txt$/, "_#{counter}.txt")
    counter += 1
  end
  filename
end

# ====================== PARSING FUNCTIONS ======================
def parse_dns_output(tool, raw_output)
  return raw_output if raw_output.empty?

  if tool == "dig"
    lines = raw_output.lines.map(&:strip).reject(&:empty?)
    answers = lines.select { |l| l.include?(" IN ") }
    answers.empty? ? "No records found" : answers.join("\n  ")
  elsif tool == "nslookup"
    lines = raw_output.lines.select { |l| l.include?("Address:") || l.include?("Name:") }
    lines.empty? ? "No records found" : lines.join("\n  ")
  else
    raw_output
  end
end

def parse_urls_output(raw_output)
  raw_output.lines.map(&:strip).reject(&:empty?).first(10)
end

def parse_ports_output(raw_output)
  raw_output.lines.map(&:strip).reject(&:empty?)
end

# ====================== CLI OPTIONS ======================
if ARGV[0] == "doctor"
  run_doctor
  exit 0
end

options = {
  dns:    "dig",
  urls:   "waybackurls",
  http:   "built-in",
  ports:  nil,
  input:  nil,
  domain: nil,
  raw:    false
}

OptionParser.new do |opts|
  opts.banner = <<~BANNER

    #{c("SubClaw v1.5", 36)} — Fast Subdomain Recon Tool
    #{c("Developed by Zuhaib Ullah Baig • https://github.com/zuhaibullahbaig", 33)}

    Usage Examples:
      subclaw subfinder_output.txt
      subclaw --domain example.com
      subclaw --domain example.com --raw
      subclaw --domain example.com --dns nslookup --ports nmap
      subclaw -i subs.txt --urls gau --http curl
      subclaw doctor
      subclaw --help

    Options:
  BANNER

  opts.on("-i", "--input FILE", "Input file with subdomains") { |v| options[:input] = v }
  opts.on("--domain DOMAIN", "Auto-run subfinder on this domain") { |v| options[:domain] = v }
  opts.on("--raw", "Show raw tool output without parsing") { options[:raw] = true }
  opts.on("--dns TOOL", "DNS tool (dig / nslookup / custom) [default: dig]") { |v| options[:dns] = v }
  opts.on("--urls TOOL", "URL history tool (waybackurls / gau / custom) [default: waybackurls]") { |v| options[:urls] = v }
  opts.on("--http TOOL", "HTTP tool (built-in / curl) [default: built-in]") { |v| options[:http] = v }
  opts.on("--ports TOOL", "Port scanner (masscan / nmap) — optional") { |v| options[:ports] = v }
  opts.on("-h", "--help", "Show this help") { puts opts; exit }
end.parse!

# ====================== INPUT LOGIC ======================
if options[:domain]
  puts c("Running subfinder on #{options[:domain]}...", 33)
  temp_file = "/tmp/subclaw_#{SecureRandom.hex(8)}.txt"
  system("subfinder -d #{options[:domain]} -o #{temp_file} -silent 2>/dev/null")
  input_file = temp_file
elsif options[:input]
  input_file = options[:input]
else
  puts c("\nSubClaw v1.5", 36)
  puts "Usage: subclaw [options] <subdomains.txt>"
  puts "       subclaw --domain example.com"
  puts "       subclaw --help"
  exit 0
end

unless File.exist?(input_file) && !File.zero?(input_file)
  puts c("ERROR: No subdomains found!", 31)
  exit 1
end

# ====================== TOOL CONFIGURATION ======================
puts c("\n=== SubClaw v1.5 Starting ===\n", 36)
puts "Developed by Zuhaib Ullah Baig | https://github.com/zuhaibullahbaig"

puts "\n#{c("Tool Configuration:", 33)}"
puts "  DNS          : #{options[:dns]}"
puts "  URL History  : #{options[:urls]}"
puts "  HTTP         : #{options[:http]}"
puts "  Port Scan    : #{options[:ports] || 'Disabled'}"
puts "  Raw Mode     : #{options[:raw] ? 'ENABLED' : 'Disabled'}"
puts ""

# ====================== WARNINGS ======================
def warn_missing(tool, category)
  return unless tool && !command_exists(tool)
  puts c("⚠️  Warning: #{tool} not found for #{category}", 33)
end

warn_missing("subfinder", "Subdomain Discovery") if options[:domain]
warn_missing(options[:dns], "DNS")
warn_missing(options[:urls], "URL History")
warn_missing("curl", "HTTP") if options[:http] == "curl"
warn_missing(options[:ports], "Port Scan") if options[:ports]

# ====================== HELPER FUNCTIONS ======================
def run_cmd(cmd)
  stdout, _, status = Open3.capture3(cmd)
  status.success? ? stdout.strip : ""
end

def get_dns(sub, tool, raw_mode)
  return "Tool not available" unless command_exists(tool)
  raw = if tool == "dig"
          run_cmd("dig +short A AAAA CNAME MX NS TXT #{sub} 2>/dev/null")
        elsif tool == "nslookup"
          run_cmd("nslookup #{sub} 2>/dev/null")
        else
          run_cmd("#{tool} #{sub} 2>/dev/null")
        end
  raw_mode ? raw : parse_dns_output(tool, raw)
end

def get_urls(sub, tool, raw_mode)
  return [] unless command_exists(tool) || command_exists("gau")
  effective = command_exists(tool) ? tool : "gau"
  raw = run_cmd("#{effective} #{sub} 2>/dev/null | head -10")
  raw_mode ? raw.lines.map(&:strip) : parse_urls_output(raw)
end

def get_http(sub, tool, raw_mode)
  if tool == "curl" && command_exists("curl")
    raw = run_cmd("timeout 2 curl -I -s -L https://#{sub} 2>/dev/null || timeout 2 curl -I -s -L http://#{sub} 2>/dev/null")
    raw_mode ? raw : (raw[/HTTP\/\d\.\d (\d+)/, 1] || "NO-REPLY")
  else
    ["https", "http"].each do |scheme|
      begin
        Timeout.timeout(2) do
          uri = URI("#{scheme}://#{sub}")
          http = Net::HTTP.new(uri.host, uri.port)
          http.open_timeout = 2
          http.read_timeout = 2
          http.use_ssl = (scheme == "https")
          resp = http.get("/", { "User-Agent" => "SubClaw/1.5" })
          return raw_mode ? "HTTP #{resp.code}" : resp.code
        end
      rescue
        next
      end
    end
    raw_mode ? "NO-REPLY" : "NO-REPLY"
  end
end

def get_ports(sub, tool, raw_mode)
  return nil unless tool && command_exists(tool)
  raw = if tool == "masscan"
          run_cmd("masscan #{sub} -p1-1000 --rate=800 --wait=0 2>/dev/null | grep -E 'open'")
        elsif tool == "nmap"
          run_cmd("nmap -T4 -F --open #{sub} 2>/dev/null")
        else
          run_cmd("#{tool} #{sub} 2>/dev/null")
        end
  raw_mode ? raw : parse_ports_output(raw)
end

# ====================== MAIN LOOP ======================
File.readlines(input_file).each_with_index do |line, i|
  sub = line.strip
  next if sub.empty?

  puts "\n#{c("[#{i+1}] #{sub}", 34)}"

  dns   = get_dns(sub, options[:dns], options[:raw])
  urls  = get_urls(sub, options[:urls], options[:raw])
  http  = get_http(sub, options[:http], options[:raw])
  ports = get_ports(sub, options[:ports], options[:raw])

  puts "  DNS   : #{dns.empty? ? 'No records found' : dns}"
  puts "  HTTP  : #{http}"
  puts "  URLs  : #{urls.size} archived links#{" (raw)" if options[:raw]}"
  puts "  Ports : #{ports ? ports.size : 0} open#{" (raw)" if options[:raw] && ports}" if ports && !ports.empty?

  print "\n  #{c('Interesting? (y = save report / any other key = skip / q = quit): ', 36)}"

  answer = STDIN.getch.downcase
  puts

  if answer == 'y'
    base_name = "subclaw_#{sub.gsub(/[^a-z0-9.-]/, '_')}.txt"
    filename = unique_filename(base_name)

    File.open(filename, "w") do |f|
      f.puts "SubClaw Report — #{Time.now}"
      f.puts "Subdomain      : #{sub}"
      f.puts "DNS Tool       : #{options[:dns]}"
      f.puts "DNS Records    :\n#{dns}\n\n"
      f.puts "HTTP Tool      : #{options[:http]}"
      f.puts "HTTP Status    : #{http}\n\n"
      f.puts "URLs Tool      : #{options[:urls]}"
      f.puts "Archived URLs  :\n#{urls.join("\n")}\n\n"
      if ports
        f.puts "Ports Tool     : #{options[:ports]}"
        f.puts "Open Ports     :\n#{ports.join("\n")}\n\n"
      end
      f.puts "=" * 80
    end
    puts c("   ✅ Saved → #{filename}", 32)
  elsif answer == 'q'
    puts c("   Quitting SubClaw...", 33)
    break
  else
    puts "   Skipped"
  end
end

File.delete(input_file) if options[:domain] && input_file.start_with?("/tmp/subclaw_")

puts "\n#{c("SubClaw finished!", 35)} Interesting reports saved as subclaw_*.txt"