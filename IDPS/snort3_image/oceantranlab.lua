EXTERNAL_NET = 'any'
TARGET_NET = {"10.0.9.2/24", "10.0.9.3/24"}

ips = 
{
    rules = [[
        include /usr/local/etc/rules/detect_ping.rules
    ]],
    variables =
    {
        nets = {
            EXTERNAL_NET = EXTERNAL_NET,
            TARGET_NET = TARGET_NET
        }
    }
}

alert_csv = {file = true}
alert_json = {file = true}
