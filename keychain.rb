# encoding: utf-8

def get_passwords_xml(query)
  xml = '<?xml version="1.0"?><items>'

  items = get_default_keychain_items

  if not query.empty?
    re = /#{Regexp.escape query}/i
    items = items.select {|item|
      re =~ item[:service] or re =~ item[:account]
    }
  end

  for item in items
    arg = (item[:class] + '###' + item[:account] + '###' + item[:service]).encode(xml: :attr)
    xml += %|
      <item uid=#{arg} arg=#{arg}>
        <title>#{item[:service].encode(xml: :text)}</title>
        <subtitle>#{item[:account].encode(xml: :text)}</subtitle>
      </item>
      |
  end

  xml += '</items>'

  xml
end

def get_password(query)
  cls, account, service = query.split /###/

  subcmd = case cls
    when 'inet' then 'find-internet-password'
    when 'genp' then 'find-generic-password'
  end

  `security #{subcmd} -a "#{account}" -l "#{service}" -w`.chomp
end

private
def get_default_keychain_items()
  keychain = `security default-keychain`.strip
  dump = `security dump-keychain #{keychain}`

  return parse_dump(dump)
end

private
def attr_pattern(key)
  /\s+#{key}\s*<blob>=[0-9A-Fx\s]*(?:"([^"]+?)"|.*?)$/
end

private
def parse_dump(dump)
  matches = dump.scan(/^class:\s*"(inet|genp)"$
                        (?:.|\n)*?
                        #{attr_pattern '0x00000007'}
                        (?:.|\n)*?
                        #{attr_pattern '"acct"'}
                       /xo)
  return matches.map {|m|
    {
      class: m[0] || '',
      service: m[1] || '',
      account: m[2] || '',
    }
  }
end
