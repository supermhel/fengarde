function add_ids(tag, ts, record)
  local id = record["path"] and string.match(record["path"], "/containers/(%x+)/")
  if id == nil then return 0, ts, record end
  record["docker_id"] = id
  record["docker_name"] = string.sub(id, 1, 12)
  return 1, ts, record
end
