-- Prune transport_reliability hashes by the message-ID timestamp.
-- KEYS[1] = hash key
-- ARGV[1] = cutoff in Unix milliseconds
-- ARGV[2] = "1" for dry-run (count only)
local key = KEYS[1]
local cutoff = tonumber(ARGV[1])
local dry = ARGV[2] == '1'
local accounting = string.find(key, ':accounting:', 1, true) ~= nil
local cursor = '0'
local deleted = 0

repeat
  local res = redis.call('HSCAN', key, cursor, 'COUNT', 2000)
  cursor = res[1]
  local flat = res[2]
  for i = 1, #flat, 2 do
    local field = flat[i]
    local id = flat[i + 1]
    if accounting then
      local pos = string.find(field, '\0', 1, true)
      if pos then
        id = string.sub(field, pos + 1)
      end
    end
    local ts = tonumber(string.match(id, '^(%d+)%-'))
    if ts and ts < cutoff then
      deleted = deleted + 1
      if not dry then
        redis.call('HDEL', key, field)
      end
    end
  end
until cursor == '0'

return deleted
