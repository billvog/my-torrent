const std = @import("std");
const posix = std.posix;
const net = std.net;

pub fn udpConnectToAddress(address: net.Address) !net.Stream {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
    errdefer posix.close(sockfd);
    try posix.connect(sockfd, &address.any, address.getOsSockLen());
    return net.Stream{ .handle = sockfd };
}
