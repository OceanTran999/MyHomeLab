EXTERNAL_NET = 'any'
TARGET_NET = '10.0.9.4'

ips = 
{
    rules = '/home/snorty/snort3/etc/rules/detect_ping.rules',
    variables =
    {
        nets = {
            EXTERNAL_NET = EXTERNAL_NET,
            TARGET_NET = TARGET_NET
        }
    }
}