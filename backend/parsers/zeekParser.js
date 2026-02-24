export function parseZeekLine(line) {
    if (!line || line.startsWith("#")) return null;

    const parts = line.trim().split(/\s+/);

    return {
        timestamp: parts[0],
        uid: parts[1],
        src_ip: parts[2],
        dst_ip: parts[4],
        protocol: parts[6],
        service: parts[7],
        duration: parts[8]
    };
}