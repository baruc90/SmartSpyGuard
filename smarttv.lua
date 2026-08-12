
local smartv_proto = Proto("SmartTVTelem", "Smart TV Telemetry")

local pf_event   = ProtoField.string("smarttv.event", "Evento")
local pf_channel = ProtoField.string("smarttv.channel", "Canal")
local pf_content = ProtoField.string("smarttv.contentId", "Contenido ID")
smartv_proto.fields = { pf_event, pf_channel, pf_content }

local http_host_field = Field.new("http.host")
local http_file_data = Field.new("http.file_data")

function smartv_proto.dissector(buffer, pinfo, tree)
    local host_extracted = http_host_field()
    if not host_extracted then
        return  
    end
    local host = tostring(host_extracted)

    local suspicious_domains = {
        "lgsmartad.com",
        "ngfts.lge.com",
        "samsungacr.com",
        "log-ingestion-eu.samsungacr.com"
    }

    local is_telemetry = false
    for _, domain in ipairs(suspicious_domains) do
        if host:find(domain, 1, true) then
            is_telemetry = true
            break
        end
    end

    if not is_telemetry then
        return
    end


    pinfo.cols.protocol = "SmartTVTelemetry"

    local subtree = tree:add(smartv_proto, buffer(), "Telemetría Smart TV")
    subtree:add_expert_info(PI_SECURITY, PI_WARN, "Datos de telemetría "  host)

    local body_extracted = http_file_data()
    if body_extracted then
        local body_str = tostring(body_extracted)
        local json_ok, json_data = pcall(require("json").decode, body_str)
        if json_ok and json_data then
            subtree:add(pf_event, json_data.event or "N/A")
            subtree:add(pf_channel, json_data.channel or "N/A")
            subtree:add(pf_content, json_data.contentId or "N/A")
        end
    end

    pinfo.cols.info:prepend("[TELEMETRÍA] ")
end

register_postdissector(smartv_proto)