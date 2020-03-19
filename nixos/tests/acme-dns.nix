# TODO: Test services.acme-dns.server.api.tls once
# https://github.com/joohoi/acme-dns/issues/214 is fixed.

{ ... }@args:

import ./acme.nix ({ dnsTestConfig = {
  dnsserver = { nodes, pkgs, ... }: {
    networking.firewall.allowedTCPPorts = [ 8053 53 ];
    networking.firewall.allowedUDPPorts = [ 53 ];
    services.acme-dns.server = {
      enable = true;
      general = {
        domain = "acme-dns.example.com";
        nsadmin = "hostmaster.example.com";
        records = [
          "example.com. A ${nodes.webserver.config.networking.primaryIPAddress}"
          # TODO FIXME: why do CNAMEs not work here?
          "a.example.com. A ${nodes.webserver.config.networking.primaryIPAddress}"
          "b.example.com. A ${nodes.webserver.config.networking.primaryIPAddress}"
          "c.example.com. A ${nodes.webserver.config.networking.primaryIPAddress}"
          # "a.example.com. CNAME example.com."
          # "b.example.com. CNAME example.com."
          # "c.example.com. CNAME example.com."
          "example.com. NS acme-dns.example.com."
          # TODO: _acme-challenge

          "acme-dns.example.com. A ${nodes.dnsserver.config.networking.primaryIPAddress}"
          "acme-dns.example.com. NS acme-dns.example.com."

          "standalone.com. A ${nodes.acmeStandalone.config.networking.primaryIPAddress}"
          "standalone.com. NS acme-dns.example.com."

          "acme-v02.api.letsencrypt.org. A ${nodes.letsencrypt.config.networking.primaryIPAddress}"
          "acme-v02.api.letsencrypt.org. NS acme-dns.example.com."
        ];
      };
      api.ip = "0.0.0.0";
    };
  };

  webserverDnsExtraConfig = { nodes, ... }: {
    security.acme.certs."example.com".dnsPropagationCheck = true;
    services.acme-dns.client = {
      enable = true;
      domains."example.com" = { server = "http://acme-dns.example.com:8053"; };
    };
  };

  setUpDnsServer = { ... }: ''
    dnsserver.wait_for_unit("acme-dns.service")
    dnsserver.wait_for_open_port(53)
    dnsserver.wait_for_open_port(8053)
  '';
}; } // args)
